//! The note store: what the wallet holds, and the one-live-transfer rule.
//!
//! `formal/baserail.qnt` (`splitRecords`): two live transfers over one note
//! can deadlock each other's records — both notes consumed, nobody paid, no
//! adversary required. The rule that restores liveness is enforced here:
//! **a note with an in-flight spend cannot fund a second one**. Rebroadcast
//! goes through the sign-log replay, never through a new transfer.

use std::collections::HashMap;
use uv_kernel2::amount::Amount;

use serde::{Deserialize, Serialize};
use uv_air::wots::Digest;
use uv_kernel2::digest;
use uv_kernel2::note::Note;

use crate::accept::Lineage;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoteState {
    /// Held, no spend signed.
    Unspent,
    /// A spend is signed and logged; its record is not yet final.
    InFlight,
    /// This note's own spend settled — the note is gone.
    Spent,
    /// A reorg invalidated part of this note's ancestry after acceptance;
    /// frozen pending re-validation ([`crate::reconcile`]).
    Quarantined,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Held {
    pub note: Note,
    /// Derivation index of this note's keys under the wallet seed.
    pub key_index: u64,
    /// The ancestry that travels when this note is spent onward.
    pub lineage: Lineage,
    pub state: NoteState,
}

/// Why a spend attempt was refused by the store.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Another note already uses this derivation index, so they would share a
    /// one-time signing key. See [`Store::insert`].
    IndexReused(u64),
    UnknownNote,
    /// The one-live-transfer rule: this note already has an in-flight spend —
    /// replay it (sign-log) instead of building a second one.
    AlreadyInFlight,
    /// Spent or quarantined notes fund nothing.
    NotSpendable,
}

/// Map keys are hex of the canonical commitment bytes: JSON requires string
/// keys, and one text-safe key form keeps the persisted wallet inspectable.
fn key(d: &Digest) -> String {
    hex_of(&digest::encode(d))
}

fn hex_of(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    notes: HashMap<String, Held>,
    /// Next unused key-derivation index.
    pub next_index: u64,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a note into the wallet.
    ///
    /// **Refuses a `key_index` the wallet already holds.** A one-time signing
    /// key is derived from `(seed, key_index)`, so two notes sharing an index
    /// share a key — and the wallet could be asked to sign for both. The
    /// sign-log now refuses that outright, and this is the layer in front of
    /// it: a receiver takes `key_index` straight off the wire from whoever
    /// paid them, and two payers holding the same address file will both start
    /// at slot zero without either doing anything wrong.
    ///
    /// Re-inserting the *same* note is idempotent, which the scan path relies
    /// on.
    pub fn insert(&mut self, held: Held) -> Result<(), StoreError> {
        let k = key(&held.note.commitment());
        if !self.notes.contains_key(&k)
            && self.notes.values().any(|h| h.key_index == held.key_index)
        {
            return Err(StoreError::IndexReused(held.key_index));
        }
        self.notes.insert(k, held);
        Ok(())
    }

    pub fn get(&self, commitment: &Digest) -> Option<&Held> {
        self.notes.get(&key(commitment))
    }

    /// Claim a note for spending. Enforces the one-live-transfer rule; the
    /// caller transitions it to `InFlight` only after the sign-log write.
    pub fn spendable(&self, commitment: &Digest) -> Result<&Held, StoreError> {
        let held = self.get(commitment).ok_or(StoreError::UnknownNote)?;
        match held.state {
            NoteState::Unspent => Ok(held),
            NoteState::InFlight => Err(StoreError::AlreadyInFlight),
            NoteState::Spent | NoteState::Quarantined => Err(StoreError::NotSpendable),
        }
    }

    /// Move a held note to a new state.
    ///
    /// Returns `UnknownNote` rather than doing nothing. Silently succeeding on
    /// a note that is not there is only safe while every caller happens to
    /// have looked it up first — which they all do today, some of them forty
    /// lines earlier. A state transition that quietly evaporates is how a note
    /// stays `Unspent` after its record went out.
    pub fn set_state(&mut self, commitment: &Digest, state: NoteState) -> Result<(), StoreError> {
        let h = self
            .notes
            .get_mut(&key(commitment))
            .ok_or(StoreError::UnknownNote)?;
        h.state = state;
        Ok(())
    }

    /// Allocate a fresh key index (change and dummy notes draw from here).
    pub fn allocate_index(&mut self) -> u64 {
        let i = self.next_index;
        self.next_index += 1;
        i
    }

    pub fn iter(&self) -> impl Iterator<Item = &Held> {
        self.notes.values()
    }
}

/// Which notes to spend to cover `target`, and how much comes from each.
///
/// **Why a payment can need more than one note.** A transfer has exactly one
/// input, so a wallet holding two notes of 1 that owes 2 cannot pay with a
/// single transfer at all — it has to send two. That limitation is in the
/// circuit and is not going away soon (spec/99 `[MERGE]`); this is the wallet
/// working around it by making several independent payments that happen to add
/// up.
///
/// Returns `None` when the spendable balance is short, so the caller can refuse
/// **before** publishing anything. A payment that gets halfway and stops is far
/// worse than one that never starts.
///
/// Three details that are each load-bearing:
///
/// - **Asset-filtered.** The old single-note selection ignored the asset and
///   read it off whichever note it picked, so a two-asset wallet could build a
///   bundle the payee would reject. Combining notes makes that a certainty
///   rather than a possibility.
/// - **Zero-amount notes excluded.** `send` mints a genuine zero-amount change
///   note whenever a payment is exact, so a wallet accumulates them. A greedy
///   loop that picked one would make no progress and spin forever.
/// - **Deterministic order.** `Store` is a `HashMap`, so iteration order varies
///   between runs. Largest-first minimises the number of notes — and therefore
///   the number of Bitcoin records, address slots and proofs a payment costs —
///   with the commitment as a tiebreak so two runs of the same wallet choose
///   the same notes.
pub fn select(store: &Store, asset: &Digest, target: Amount) -> Option<Vec<(Digest, Amount)>> {
    let mut candidates: Vec<&Held> = store
        .iter()
        .filter(|h| h.state == NoteState::Unspent && h.note.asset == *asset && h.note.amount.0 > 0)
        .collect();
    candidates.sort_by(|a, b| {
        b.note.amount.0.cmp(&a.note.amount.0).then_with(|| {
            uv_kernel2::digest::encode(&a.note.commitment())
                .cmp(&uv_kernel2::digest::encode(&b.note.commitment()))
        })
    });

    let mut picked = Vec::new();
    let mut remaining = target.0;
    for h in candidates {
        if remaining == 0 {
            break;
        }
        let part = remaining.min(h.note.amount.0);
        picked.push((h.note.commitment(), Amount(part)));
        remaining -= part;
    }
    if remaining > 0 {
        return None;
    }
    Some(picked)
}

#[cfg(test)]
mod selection {
    use super::*;
    use uv_kernel2::keys::{derive, WalletSeed};
    use uv_kernel2::note::Note;

    fn asset(tag: u32) -> Digest {
        [p3_baby_bear::BabyBear::new(tag); 8]
    }

    fn held(seed: u8, idx: u64, a: Digest, v: u64, state: NoteState) -> Held {
        let keys = derive(&WalletSeed([seed; 32]), idx);
        Held {
            note: Note::build(a, Amount(v), &keys),
            key_index: idx,
            lineage: Vec::new(),
            state,
        }
    }

    #[test]
    fn two_small_notes_can_cover_what_neither_can_alone() {
        let a = asset(1);
        let mut s = Store::new();
        s.insert(held(1, 0, a, 1, NoteState::Unspent))
            .expect("fresh index");
        s.insert(held(1, 1, a, 1, NoteState::Unspent))
            .expect("fresh index");
        let picked = select(&s, &a, Amount(2)).expect("1 + 1 covers 2");
        assert_eq!(picked.len(), 2);
        assert_eq!(picked.iter().map(|(_, v)| v.0).sum::<u64>(), 2);
    }

    #[test]
    fn one_note_is_preferred_when_it_covers_the_whole_amount() {
        // Each extra note costs a Bitcoin record, an address slot and a proof.
        let a = asset(1);
        let mut s = Store::new();
        s.insert(held(1, 0, a, 5, NoteState::Unspent))
            .expect("fresh index");
        s.insert(held(1, 1, a, 1, NoteState::Unspent))
            .expect("fresh index");
        s.insert(held(1, 2, a, 1, NoteState::Unspent))
            .expect("fresh index");
        let picked = select(&s, &a, Amount(3)).expect("5 covers 3");
        assert_eq!(picked.len(), 1, "largest-first should use the single note");
        assert_eq!(picked[0].1, Amount(3));
    }

    #[test]
    fn a_short_balance_refuses_rather_than_paying_partially() {
        let a = asset(1);
        let mut s = Store::new();
        s.insert(held(1, 0, a, 1, NoteState::Unspent))
            .expect("fresh index");
        assert!(select(&s, &a, Amount(2)).is_none());
    }

    #[test]
    fn unspendable_notes_are_not_counted() {
        let a = asset(1);
        let mut s = Store::new();
        s.insert(held(1, 0, a, 5, NoteState::InFlight))
            .expect("fresh index");
        s.insert(held(1, 1, a, 5, NoteState::Spent))
            .expect("fresh index");
        s.insert(held(1, 2, a, 5, NoteState::Quarantined))
            .expect("fresh index");
        assert!(
            select(&s, &a, Amount(1)).is_none(),
            "none of those are spendable"
        );
    }

    #[test]
    fn another_assets_notes_are_not_counted() {
        let (a, b) = (asset(1), asset(2));
        let mut s = Store::new();
        s.insert(held(1, 0, b, 100, NoteState::Unspent))
            .expect("fresh index");
        assert!(
            select(&s, &a, Amount(1)).is_none(),
            "wrong asset must not fund"
        );
    }

    /// `send` mints a genuine zero-amount change note on an exact payment, so a
    /// wallet accumulates them. A greedy loop that picked one would never make
    /// progress.
    #[test]
    fn zero_amount_change_notes_cannot_stall_the_loop() {
        let a = asset(1);
        let mut s = Store::new();
        for i in 0..5 {
            s.insert(held(1, i, a, 0, NoteState::Unspent))
                .expect("fresh index");
        }
        s.insert(held(1, 9, a, 2, NoteState::Unspent))
            .expect("fresh index");
        let picked = select(&s, &a, Amount(2)).expect("the one real note covers it");
        assert_eq!(picked.len(), 1);
    }

    #[test]
    fn selection_is_the_same_on_every_run() {
        let a = asset(1);
        let mut s = Store::new();
        for i in 0..8 {
            s.insert(held(1, i, a, 1, NoteState::Unspent))
                .expect("fresh index");
        }
        let first = select(&s, &a, Amount(4)).unwrap();
        for _ in 0..8 {
            assert_eq!(
                select(&s, &a, Amount(4)).unwrap(),
                first,
                "HashMap order leaked"
            );
        }
    }
}
