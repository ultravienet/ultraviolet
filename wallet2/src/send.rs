//! The send path, in the order the disciplines demand.
//!
//! 1. The store confirms the note is spendable (one-live-transfer rule).
//! 2. If the sign-log already holds this note's spend, **replay it** — the
//!    identical payload, the identical record — and sign nothing.
//! 3. Otherwise build the two outputs (payment + change; a zero-amount change
//!    note when the payment consumes the whole input), prove in the hiding
//!    configuration, and **log the payload before any broadcast** — between
//!    signing and logging there must be no window in which a crash leaves a
//!    signature the wallet cannot remember making.
//! 4. Only then publish the record.
//!
//! The recipient's note fields (nullifier key, randomness) arrive
//! from the address/KEM layer (`SPEC.md` §6); this module takes them as given.

use uv_air::poseidon2::Digest;
use uv_air::prove::{HidingConfig, Vouched};
use uv_kernel2::amount::Amount;
use uv_kernel2::keys::{derive, NoteKeys, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer::Transfer;
use uv_kernel2::transfer_prove::prove_hiding;

use crate::accept::{Hop, MAX_LINEAGE};
use crate::chain::Chain;
use crate::signlog::{LogError, SignLog, SignedSpend};
use crate::store::{NoteState, Store, StoreError};

/// The recipient-side fields of an output note, as delivered by the address
/// layer.
/// What a payee publishes so anyone can build a note for them. Both are
/// **public**: the anchor is `H(nullifier_key)`, so handing it over does not let
/// the payer compute the nullifier this note will one day reveal. There is no
/// `owner_pk` — the note carries none (spec/99 `[PROOF-AUTH]`).
pub struct Recipient {
    pub nullifier_anchor: Digest,
    pub randomness: Digest,
}

/// Why a send was refused.
#[derive(Debug)]
pub enum SendError {
    Store(StoreError),
    /// Payment exceeds the input note's value.
    Insufficient,
    /// The sign-log refused: this key already signed a different payload.
    /// This is the wallet protecting its own key — investigate, never force.
    Log(LogError),
    /// The wallet could not be written to durable storage, so nothing was
    /// published. Safe: the spend is signed but unbroadcast, and re-running
    /// replays the identical payload once the write problem is fixed.
    NotPersisted(String),
    /// Spending this note would build a lineage the receiver must refuse.
    ///
    /// **This is a fund-loss path, closed 2026-07-30.** Nothing checked the
    /// length on the way out: `prepare` pushed a hop unconditionally, so
    /// spending a note already at `MAX_LINEAGE` produced a bundle one hop too
    /// long. The payer paid a real Bitcoin fee, burned a payee slot, and marked
    /// the note in-flight — and the payee refused it and **deleted the bundle**,
    /// which was the only surviving copy of the lineage. Nothing in the test
    /// suite came within 250 hops of finding it.
    ///
    /// Refused here, before any proving or broadcasting, so the note stays
    /// spendable and the money stays where it is. The holder's options are the
    /// issuer's redemption cycle or waiting for the accumulator (spec/99
    /// `[ACC]`), which removes per-hop ancestry and this limit with it.
    LineageTooLong {
        would_be: usize,
        max: usize,
    },
    /// The record could not be published.
    ///
    /// Reachable and recoverable, which is the point of returning it rather
    /// than panicking as this path used to. By the time broadcasting is
    /// attempted the spend is signed *and* durable, so the state left behind is
    /// exactly the one the replay path exists for: retry, and the identical
    /// bytes go out again.
    NotPublished(String),
}

/// A wallet's own moving parts, grouped so [`prepare`] reads as "this wallet
/// spends": the store (one-live-transfer rule), the sign-log (replay
/// discipline), and the seed (key derivation).
pub struct WalletCtx<'a> {
    pub store: &'a mut Store,
    pub log: &'a mut SignLog,
    pub seed: &'a WalletSeed,
}

/// The outcome: the transfer as broadcast, and the new hop for the recipient's
/// lineage.
pub struct Sent {
    pub transfer: Transfer,
    pub hop: Hop,
    /// The change note, and its keys. **`None` on a replay** — a replay creates
    /// no new note, and these used to be filled with the *input* note and the
    /// input note's own secrets, handed to a caller that
    /// believed it held freshly-derived change keys. No caller read them, which
    /// is the only reason that was not a disclosure. `Option` makes the shape
    /// say what the doc comment used to only claim.
    pub change: Option<(Note, NoteKeys)>,
    /// True when the sign-log replayed an existing payload: no new signature
    /// was made and no new proof was generated.
    pub replayed: bool,
}

/// A spend that has been signed and logged, but **not yet broadcast**.
///
/// The type exists to make an ordering impossible to get wrong. The sign-log
/// entry must reach durable storage before the record reaches Bitcoin: a crash
/// in between leaves a signature the wallet cannot remember making, and the
/// retry — taking a different address slot, since reservations *are* already
/// durable — signs a second different message with the same one-time key.
///
/// `prepare` takes no chain and cannot broadcast. `broadcast` consumes this and
/// does nothing else. The caller's `save_wallet` goes between them, and there
/// is no way to write the sequence in the other order.
#[must_use = "a prepared spend is signed but not broadcast; persist the wallet, then broadcast it"]
pub struct PreparedSpend {
    record: Record,
    sent: Sent,
}

impl PreparedSpend {
    /// What will be published. Readable so a caller can log or display it
    /// before committing; publishing is [`broadcast`]'s job alone.
    pub fn record(&self) -> &Record {
        &self.record
    }
}

/// Sign and log a spend of `input_commitment`, paying `amount` to `recipient`.
///
/// Deliberately takes no chain: nothing here can broadcast. Persist the wallet,
/// then hand the result to [`broadcast`].
pub fn prepare(
    config: &Vouched<HidingConfig>,
    wallet: WalletCtx<'_>,
    input_commitment: &Digest,
    recipient: &Recipient,
    amount: Amount,
) -> Result<PreparedSpend, SendError> {
    let WalletCtx { store, log, seed } = wallet;
    // Replay path FIRST: if this key ever signed, the only permissible action
    // is rebroadcasting those identical bytes — including (especially) when
    // the note is marked in-flight, which is exactly when a lost record race
    // makes rebroadcast necessary.
    let held_index = store
        .get(input_commitment)
        .ok_or(SendError::Store(StoreError::UnknownNote))?
        .key_index;
    if let Some(existing) = log.get(held_index) {
        return Ok(replay_of(existing));
    }

    let held = store
        .spendable(input_commitment)
        .map_err(SendError::Store)?;
    let input = held.note.clone();
    let key_index = held.key_index;

    // Refuse *before* proving, paying a fee, or burning a payee slot: this hop
    // would make the lineage longer than any receiver will look at, and a
    // receiver that refuses it is behaving correctly. Sending anyway spends
    // real money to produce a bundle whose only possible outcome is refusal.
    let would_be = held.lineage.len() + 1;
    if would_be > MAX_LINEAGE {
        return Err(SendError::LineageTooLong {
            would_be,
            max: MAX_LINEAGE,
        });
    }

    let change_amount = input
        .amount
        .checked_sub(amount)
        .ok_or(SendError::Insufficient)?;

    // Build the outputs: payment to the recipient, change to a fresh key of
    // our own — a genuine zero-amount note when the payment is exact, which
    // keeps every hop the same two-output shape (`SPEC.md` §8).
    let payment = Note {
        asset: input.asset,
        amount,
        nullifier_anchor: recipient.nullifier_anchor,
        randomness: recipient.randomness,
    };
    let change_index = store.allocate_index();
    let change_keys = derive(seed, change_index);
    let change = Note::build(input.asset, change_amount, &change_keys);

    let input_keys = derive(seed, key_index);
    let (transfer, proof) = prove_hiding(
        config,
        &input,
        &input_keys,
        [&payment, &change],
        &lineage_digest(store, input_commitment),
    );
    let proof_bytes = bincode::serialize(&proof).expect("proof serializes");

    // Cache the exact spend against the note's index, so a lost-record retry
    // resends identical bytes — see `SignLog`. No signature is made here.
    log.put(
        key_index,
        SignedSpend {
            transfer: transfer.clone(),
            proof: proof_bytes.clone(),
        },
    )
    .map_err(SendError::Log)?;
    store
        .set_state(input_commitment, NoteState::InFlight)
        .map_err(SendError::Store)?;

    let record = Record {
        nullifier: transfer.nullifier,
        bundle_hash: transfer.bundle_hash(),
    };

    // Stash the change note (its lineage is the input's plus this hop).
    let hop = Hop {
        transfer: transfer.clone(),
        proof: proof_bytes,
    };
    let mut change_lineage = store
        .get(input_commitment)
        .expect("checked above")
        .lineage
        .clone();
    change_lineage.push(hop.clone());
    // `allocate_index` hands out a fresh index, so this cannot collide — but
    // it is checked rather than assumed, which is the whole point of the
    // exercise.
    store
        .insert(crate::store::Held {
            note: change.clone(),
            key_index: change_index,
            lineage: change_lineage,
            state: NoteState::Unspent,
        })
        .map_err(SendError::Store)?;

    Ok(PreparedSpend {
        record,
        sent: Sent {
            transfer,
            hop,
            change: Some((change, change_keys)),
            replayed: false,
        },
    })
}

/// Rebuild the prepared spend a logged payload describes. Signs nothing.
fn replay_of(existing: &SignedSpend) -> PreparedSpend {
    let transfer = existing.transfer.clone();
    PreparedSpend {
        record: Record {
            nullifier: transfer.nullifier,
            bundle_hash: transfer.bundle_hash(),
        },
        sent: Sent {
            hop: Hop {
                transfer: transfer.clone(),
                proof: existing.proof.clone(),
            },
            transfer,
            // A replay creates nothing new — see `Sent::change`.
            change: None,
            replayed: true,
        },
    }
}

/// Rebroadcast the payload this key already signed, if there is one.
///
/// The recovery path for a record that never landed: the identical bytes go
/// out again. It takes **no recipient**, because a replay pays whoever the
/// original payload paid. That is not a convenience — a caller that routed a
/// replay through [`prepare`] had to invent a recipient, and then believed the
/// resulting payment went to it. `cli` did exactly that: it reserved a fresh
/// address slot per note, and on replay mailed the payee a bundle naming that
/// slot while the transfer paid the original one. The payee refused it as
/// `NotAnOutput` and the slot was burnt for nothing.
///
/// `Ok(None)` means this key has never signed, so there is nothing to
/// rebroadcast — distinct from a rebroadcast that failed.
pub fn rebroadcast(
    chain: &mut (impl Chain + ?Sized),
    log: &SignLog,
    key_index: u64,
) -> Result<Option<Sent>, SendError> {
    match log.get(key_index) {
        // Nothing to persist: a replay creates no log entry and no note, which
        // is exactly why it is safe to send the same bytes again.
        Some(existing) => broadcast(chain, replay_of(existing), || Ok::<(), String>(())).map(Some),
        None => Ok(None),
    }
}

/// Persist the wallet, then publish the record. The only way to broadcast.
///
/// **`persist` is a parameter, not a convention.** `PreparedSpend` already made
/// "prepare before broadcast" impossible to get wrong; it did nothing about the
/// step *between* them, which is the one that matters. The sign-log entry must
/// reach durable storage before the record reaches Bitcoin — a crash in between
/// leaves a signature the wallet cannot remember making, and the retry signs a
/// second different message with the same one-time key. That is key disclosure,
/// the failure this whole module is shaped around.
///
/// The CLI did call `save_wallet` in the right place. Nothing required it to,
/// and "every caller happens to do the right thing" is precisely the shape of
/// assumption that `spec/99 [ASSUMPTIONS]` exists to hunt. Taking the persist
/// step as an argument means a caller cannot express the wrong order: there is
/// no path to `chain.publish` that does not run it first.
///
/// A failing `persist` aborts before anything is published — the spend is
/// signed but unbroadcast, which is the recoverable state (`rebroadcast`).
pub fn broadcast<E: std::fmt::Display>(
    chain: &mut (impl Chain + ?Sized),
    prepared: PreparedSpend,
    persist: impl FnOnce() -> Result<(), E>,
) -> Result<Sent, SendError> {
    persist().map_err(|e| SendError::NotPersisted(format!("{e}")))?;
    chain
        .publish(&prepared.record)
        .map_err(|e| SendError::NotPublished(format!("{e}")))?;
    Ok(prepared.sent)
}

/// The history digest the input note's next hop starts from: the fold of its
/// lineage's bundle hashes.
fn lineage_digest(store: &Store, input_commitment: &Digest) -> Digest {
    let held = store.get(input_commitment).expect("caller checked");
    let hashes: Vec<Digest> = held
        .lineage
        .iter()
        .map(|h| h.transfer.bundle_hash())
        .collect();
    uv_kernel2::history::digest_of(&hashes)
}
