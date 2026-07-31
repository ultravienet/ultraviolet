//! Spending a note at the hop cap used to destroy it. Both halves, pinned.
//!
//! **The bug.** `MAX_LINEAGE` is 256 and a receiver refuses anything longer.
//! Nothing checked the length on the way *out*: `prepare` pushed a hop
//! unconditionally, so spending a note whose lineage was already 256 hops built
//! a 257-hop bundle. The payer paid a real Bitcoin fee, burned a payee slot, and
//! marked the note in-flight. The payee then refused it — correctly — and
//! `scan_inbox` **deleted the bundle**, because `TooLong` was classified
//! permanent. The bundle was the only surviving copy of the lineage.
//!
//! One silent fund-loss path, reachable with no attacker and no bug on either
//! side beyond the missing check.
//!
//! **Why nothing found it.** Every other test in this workspace runs lineages of
//! zero to three hops. The cap sits at 256. The one existing test that touches
//! `MAX_LINEAGE` builds a lineage of dummy hops and checks the *receiver*
//! refuses it; nothing ever asked what the *sender* does at the boundary, and
//! nothing built a wallet holding a note that long. So this file does the
//! expensive thing and constructs lineages at the real limit.
//!
//! **The two halves.**
//!
//! 1. The sender refuses first, before proving or broadcasting, so the note stays
//!    spendable and no fee is paid. That is `SendError::LineageTooLong`.
//! 2. Even so, a receiver handed an over-long bundle must not delete it — by an
//!    old sender, a lowered cap, or a hostile one. `TooLong` is transient now.
//!    Note this is the one verdict that will genuinely never verify: a lineage
//!    does not get shorter. It is kept anyway, because the classifier decides
//!    *deletion* and the bundle is the only copy.

use uv_air::poseidon2::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::transfer::Transfer;
use uv_wallet2::accept::{Hop, Lineage, Rejected, MAX_LINEAGE};
use uv_wallet2::chain::MockChain;
use uv_wallet2::send::{prepare, Recipient, SendError, WalletCtx};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

const ASSET: Digest = [p3_baby_bear::BabyBear::new(0xA5); 8];

fn recipient(seed: &WalletSeed, index: u64) -> Recipient {
    let k = derive(seed, index);
    Recipient {
        nullifier_anchor: k.anchor,
        randomness: k.randomness,
    }
}

/// A structurally-shaped hop. Never verified by these tests — the length check
/// runs before any proof work, which is the property being relied on.
fn filler_hop() -> Hop {
    Hop {
        transfer: Transfer {
            input_commitment: [p3_baby_bear::BabyBear::default(); 8],
            nullifier: [p3_baby_bear::BabyBear::default(); 8],
            outputs: vec![],
            prev_history: history::GENESIS,
        },
        proof: Vec::new(),
    }
}

/// A wallet holding one note of 100 whose lineage is exactly `hops` long.
fn wallet_holding_a_note_with_lineage(hops: usize) -> (Store, SignLog, WalletSeed, Digest) {
    let payer = WalletSeed([7u8; 32]);
    let mut store = Store::default();
    let key_index = store.allocate_index();
    let keys = derive(&payer, key_index);
    let note = Note::build(ASSET, Amount(100), &keys);
    let commitment = note.commitment();
    store
        .insert(Held {
            note,
            key_index,
            lineage: vec![filler_hop(); hops],
            state: NoteState::Unspent,
        })
        .expect("fresh store");
    (store, SignLog::default(), payer, commitment)
}

// ---------------------------------------------------------------------------
// Half one: the sender refuses, and refuses for free.
// ---------------------------------------------------------------------------

/// A note already at the cap cannot be spent, and saying so costs nothing.
#[test]
fn spending_a_note_at_the_cap_is_refused_before_any_cost() {
    let (mut store, mut log, payer, commitment) = wallet_holding_a_note_with_lineage(MAX_LINEAGE);
    let payee = WalletSeed([9u8; 32]);
    let cfg = uv_air::prove::hiding_config();

    let verdict = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &payer,
        },
        &commitment,
        &recipient(&payee, 0),
        Amount(10),
    );

    match verdict {
        Err(SendError::LineageTooLong { would_be, max }) => {
            assert_eq!(would_be, MAX_LINEAGE + 1);
            assert_eq!(max, MAX_LINEAGE);
        }
        Err(other) => panic!("expected LineageTooLong, got {other:?}"),
        Ok(_) => panic!(
            "prepare SUCCEEDED on a note already at the cap — this is the fund-loss \
             path: a fee is paid and a slot burned for a bundle the payee must refuse"
        ),
    }

    // The refusal must leave the wallet exactly as it found it. If any of these
    // moved, the payer has been charged for a payment that cannot be received.
    assert!(
        log.get(store.get(&commitment).expect("note still held").key_index)
            .is_none(),
        "nothing may be logged: a logged spend can never be re-prepared, so this \
         would strand the note permanently"
    );
    assert_eq!(
        store.get(&commitment).expect("note still held").state,
        NoteState::Unspent,
        "the note must stay spendable — the whole point is that no money moved"
    );
}

/// One hop below the cap still works, so the guard is a boundary and not a wall.
///
/// Without this, `prepare` could refuse *every* spend and the test above would
/// still pass.
#[test]
fn a_note_one_hop_below_the_cap_can_still_be_spent() {
    let (mut store, mut log, payer, commitment) =
        wallet_holding_a_note_with_lineage(MAX_LINEAGE - 1);
    let payee = WalletSeed([9u8; 32]);
    let cfg = uv_air::prove::hiding_config();

    let verdict = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &payer,
        },
        &commitment,
        &recipient(&payee, 0),
        Amount(10),
    );

    assert!(
        !matches!(verdict, Err(SendError::LineageTooLong { .. })),
        "a lineage of {} must still be spendable — it produces exactly {}, \
         which is the cap and not past it",
        MAX_LINEAGE - 1,
        MAX_LINEAGE
    );
    assert!(
        verdict.is_ok(),
        "expected a prepared spend, got {:?}",
        verdict.err()
    );
}

/// An ordinary note is untouched by any of this.
#[test]
fn a_short_lineage_is_unaffected() {
    let (mut store, mut log, payer, commitment) = wallet_holding_a_note_with_lineage(2);
    let payee = WalletSeed([9u8; 32]);
    let cfg = uv_air::prove::hiding_config();
    let verdict = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &payer,
        },
        &commitment,
        &recipient(&payee, 0),
        Amount(10),
    );
    assert!(verdict.is_ok(), "got {:?}", verdict.err());
}

// ---------------------------------------------------------------------------
// Half two: the receiver refuses without destroying.
// ---------------------------------------------------------------------------

/// The receiver still refuses an over-long lineage — the DoS defence is intact.
#[test]
fn the_receiver_still_refuses_an_over_long_lineage() {
    let lineage: Lineage = vec![filler_hop(); MAX_LINEAGE + 1];
    let chain = MockChain::new();
    let cfg = uv_air::prove::hiding_config();
    let note = Note::build(ASSET, Amount(1), &derive(&WalletSeed([0u8; 32]), 0));
    let verdict = uv_wallet2::accept::accept(
        &cfg,
        &chain,
        &uv_wallet2::accept::TrustAnchor {
            asset: &ASSET,
            genesis_commitment: &note.commitment(),
            issued_below: None,
            genesis_amount: 1,
        },
        &note,
        &lineage,
    );
    assert!(
        matches!(verdict, Err(Rejected::TooLong(n)) if n == MAX_LINEAGE + 1),
        "got {verdict:?}"
    );
}

/// ...but it must not delete the bundle, which is the only copy of the lineage.
///
/// This is the assertion that would have caught the fund loss. `is_permanent`
/// drives `scan_inbox`'s `remove_file`, so `true` here means the evidence is
/// gone and the coin is unrecoverable even if the cap is later raised.
#[test]
fn an_over_long_lineage_is_never_destroyed() {
    assert!(
        !Rejected::TooLong(MAX_LINEAGE + 1).is_permanent(),
        "TooLong must not authorise deletion: the bundle is the only copy of the \
         lineage, and a raised cap, a repaired sender, or the accumulator could \
         still make the coin spendable"
    );
}
