//! Regression test: a replay is a rebroadcast, not a second payment.
//!
//! **The bug.** `send::prepare` takes a recipient, and on the replay path it
//! ignores it — correctly, because a replay re-publishes bytes that were signed
//! once and can never be signed again. But the CLI could not see that from the
//! signature. It reserved a fresh address slot for every note in a payment,
//! called `prepare` with that slot's keys, and then mailed the payee a bundle
//! saying "your output is slot N". On a replay the transfer paid the *original*
//! slot, so the payee derived the wrong keys, refused the bundle as
//! `NotAnOutput` — a permanent rejection — and a slot was burnt for a payment
//! that never happened. Retry to recover a lost record, lose a slot each time.
//!
//! It failed closed, which is why it survived: no money moved anywhere it
//! should not. It cost liveness and it cost the scarcest thing a one-time-key
//! wallet has.
//!
//! **The fix has two halves, and this pins both.**
//!
//! 1. `send::rebroadcast` takes no recipient at all, so the shape of the API
//!    says what the replay path does. That is what the first test checks: the
//!    republished transfer is byte-identical to the original, and in particular
//!    still pays the original payee.
//! 2. The caller partitions replays out *before* reserving anything. That is
//!    the CLI's job and `demo/local2.sh` checks it end to end; here we check the
//!    piece the CLI relies on — that "has this key signed?" is answerable from
//!    the sign-log alone, with no chain and no slot.

use uv_air::poseidon2::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_wallet2::accept::Lineage;
use uv_wallet2::chain::{Chain, Lookup, MockChain};
use uv_wallet2::send::{broadcast, prepare, rebroadcast, Recipient, WalletCtx};
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

/// A wallet holding one note of 100, and the payee's seed.
fn funded() -> (Store, SignLog, WalletSeed, WalletSeed, Digest) {
    let payer = WalletSeed([7u8; 32]);
    let payee = WalletSeed([9u8; 32]);
    let mut store = Store::default();
    // Through `allocate_index`, not a bare `0`: the store hands out indices and
    // refuses a reused one, and the change note this payment creates will draw
    // the next.
    let key_index = store.allocate_index();
    let keys = derive(&payer, key_index);
    let note = Note::build(ASSET, Amount(100), &keys);
    let commitment = note.commitment();
    store
        .insert(Held {
            note,
            key_index,
            lineage: Lineage::new(),
            state: NoteState::Unspent,
        })
        .expect("fresh store");
    (store, SignLog::default(), payer, payee, commitment)
}

/// The heart of it: a rebroadcast reproduces the original payment exactly.
#[test]
fn a_rebroadcast_republishes_the_original_payment_byte_for_byte() {
    let (mut store, mut log, payer, payee, commitment) = funded();
    let mut chain = MockChain::default();
    let cfg = uv_air::prove::hiding_config();

    // The real payment: slot 0 of the payee's address.
    let first = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &payer,
        },
        &commitment,
        &recipient(&payee, 0),
        Amount(30),
    )
    .expect("the note is spendable");
    let sent = broadcast(&mut chain, first, || Ok::<(), String>(())).expect("publishes");
    assert!(!sent.replayed);
    let original = sent.transfer.clone();

    // Now the record is lost and the payer retries. The wallet must republish
    // the same bytes — and must NOT be able to redirect them by handing over a
    // different slot, which is precisely what `rebroadcast` not taking a
    // recipient makes impossible to express.
    let again = rebroadcast(&mut chain, &log, store.get(&commitment).unwrap().key_index)
        .expect("republishes")
        .expect("this key has signed");

    assert!(again.replayed, "this is a replay, and must say so");
    assert!(
        again.change.is_none(),
        "a replay creates no note, so it hands back no keys"
    );
    assert_eq!(
        bincode::serialize(&again.transfer).unwrap(),
        bincode::serialize(&original).unwrap(),
        "a rebroadcast that differs by one byte is a second signature with a \
         one-time key"
    );
    assert_eq!(
        again.transfer.outputs, original.outputs,
        "the replay must still pay whoever the original payment paid — this is \
         the assertion the CLI's mailed bundle used to contradict"
    );

    // And the chain is unmoved: first occurrence still binds the original.
    match chain.first_occurrence(&original.nullifier) {
        Lookup::Found(o) => assert_eq!(
            o.bundle_hash,
            original.bundle_hash(),
            "the republished record must not displace the one already there"
        ),
        other => panic!("the record should be on the chain: {other:?}"),
    }
}

/// The seam the CLI partitions on, checked without a chain: whether a note is a
/// replay is knowable from the sign-log alone, *before* any slot is reserved.
/// If this needed a broadcast to find out, the burnt-slot bug could not be
/// fixed by reordering.
#[test]
fn whether_a_note_is_a_replay_is_knowable_before_reserving_anything() {
    let (mut store, mut log, payer, payee, commitment) = funded();
    let mut chain = MockChain::default();
    let cfg = uv_air::prove::hiding_config();
    let key_index = store.get(&commitment).unwrap().key_index;

    assert!(
        log.get(key_index).is_none(),
        "an unspent note is not a replay"
    );
    assert!(
        rebroadcast(&mut chain, &log, key_index)
            .expect("no error")
            .is_none(),
        "nothing to rebroadcast is `None`, not a failure"
    );

    let p = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &payer,
        },
        &commitment,
        &recipient(&payee, 0),
        Amount(30),
    )
    .expect("spendable");
    broadcast(&mut chain, p, || Ok::<(), String>(())).expect("publishes");

    assert!(
        log.get(key_index).is_some(),
        "a spent note is a replay, and the sign-log says so on its own"
    );
}

/// `set_state` on a note the store never held is an error, not a no-op.
///
/// It was a no-op, and correct only because every caller had looked the note up
/// first. A transition that quietly evaporates leaves a note `Unspent` after its
/// record went out, which is the wallet's own double-spend.
#[test]
fn setting_the_state_of_a_note_that_is_not_held_is_refused() {
    let (mut store, _log, _payer, payee, _commitment) = funded();
    let stranger = Note::build(ASSET, Amount(5), &derive(&payee, 77)).commitment();

    assert!(
        store.set_state(&stranger, NoteState::Spent).is_err(),
        "a note that was never held cannot change state"
    );
    assert!(
        store.get(&stranger).is_none(),
        "and it must not have been created by the attempt"
    );
}
