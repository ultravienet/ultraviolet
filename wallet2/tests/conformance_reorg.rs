//! Model ↔ code conformance: the real `reconcile` must agree with
//! `formal/reorg.qnt`.
//!
//! Fourth rung of the shared-source-of-truth work (spec/99
//! `[MODEL-CONFORMANCE]`, SPEC.md §11.3). The model proves two things about
//! chains that move. `shallow`: with no reconciliation, a reorg deeper than the
//! margin flips a held coin's first occurrence and the wallet never finds out —
//! `acceptedStaysValid` violated. `genesisUnchecked`: a reorg can orphan the
//! *issuance* while every spend record survives, leaving coins held that no
//! reader of Bitcoin can account for — `acceptedHasLiveGenesis` violated. The
//! real wallet claims to implement the `reconciled` rule with the genesis half
//! included. This test replays both frozen counterexamples against the real
//! `reconcile` and requires exactly that:
//!
//!   - the coin the `shallow` wallet keeps after the flip must be QUARANTINED
//!     by the real pass (found, bundle mismatch — the model's "no longer first");
//!   - when the original record is re-mined — the ordinary post-reorg outcome —
//!     the same coin must be RESTORED by the full positive check (L2);
//!   - the coin the `genesisUnchecked` wallet keeps must be QUARANTINED on the
//!     genesis half alone, with its own settlement still perfect — which this
//!     test asserts first, so the refusal provably comes from the issuance and
//!     not the ancestry.
//!
//! The mapping is structural, not numeric: the model runs at `REQUIRED = 1`
//! and flips with a 2-block rewrite; the code's floor tier is 3 confirmations,
//! so the replay mines to the code's own bar and performs the flip the trace
//! prescribes (drop the winner, mine the competitor). What is conformance-tied
//! is who wins, who is held, and what the wallet must do about it.
//!
//! The committed traces (`formal/traces/reorg_*.itf.json`) are the model's
//! frozen testimony; regeneration is a review event
//! (`formal/traces/README.md`).

use serde_json::Value;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use uv_air::prove::hiding_config;
use uv_air::wots::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::issuance::Issuance;
use uv_kernel2::keys::{derive, NoteKeys, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer_prove::prove_hiding;
use uv_wallet2::accept::{accept, Hop, Lineage, TrustAnchor};
use uv_wallet2::chain::{Chain, Lookup, MockChain};
use uv_wallet2::reconcile::{reconcile, Genesis};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

/// Small enough for the floor confirmation tier (3), large enough to be real.
const VALUE: u64 = 500;

fn asset() -> Digest {
    [BabyBear::from_u32(0x0059_0000); 8]
}

/// The one nullified note in the model (`NULLIFIERS = Set(1)`): the genesis
/// note both competing bundles spend. Same note, same keys → same nullifier,
/// which is what makes the race the model's race.
fn genesis_note() -> (Note, NoteKeys) {
    let keys = derive(&WalletSeed([0x55u8; 32]), 1);
    (Note::build(asset(), Amount(VALUE), &keys), keys)
}

/// Model bundle `b` → a real transfer of the genesis note to bundle-specific
/// outputs, with a real proof. Deterministic, so the same bundle id always
/// yields the same bytes — records published for it and lineages built from it
/// agree.
fn bundle(b: u64) -> (Note, Hop) {
    let cfg = hiding_config();
    let (input, keys) = genesis_note();
    let payment = Note::build(
        asset(),
        Amount(VALUE),
        &derive(&WalletSeed([0x66u8; 32]), b),
    );
    let change = Note::build(asset(), Amount(0), &derive(&WalletSeed([0x77u8; 32]), b));
    let (transfer, proof) =
        prove_hiding(&cfg, &input, &keys, [&payment, &change], &history::GENESIS);
    (
        payment,
        Hop {
            transfer,
            proof: bincode::serialize(&proof).expect("proof serializes"),
        },
    )
}

fn issuance() -> Issuance {
    Issuance {
        amount: VALUE,
        asset: asset(),
        commitment: genesis_note().0.commitment(),
    }
}

fn genesis_ref(iss: &Issuance) -> Genesis<'_> {
    Genesis {
        asset: &iss.asset,
        commitment: &iss.commitment,
        amount: iss.amount,
    }
}

// ---- ITF trace reading ---------------------------------------------------

fn last_state(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let v: Value = serde_json::from_str(&raw).expect("itf json");
    v["states"]
        .as_array()
        .and_then(|s| s.last())
        .cloned()
        .expect("a final state")
}

fn var<'a>(state: &'a Value, suffix: &str) -> &'a Value {
    state
        .as_object()
        .unwrap()
        .iter()
        .find(|(k, _)| k.ends_with(suffix))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("a `{suffix}` variable"))
}

fn bigint(v: &Value) -> u64 {
    v["#bigint"].as_str().unwrap().parse().unwrap()
}

/// The single held marker's bundle id (both counterexamples hold exactly one).
fn held_bundle(state: &Value) -> u64 {
    let set = var(state, "accepted")["#set"].as_array().expect("#set");
    assert_eq!(set.len(), 1, "these counterexamples hold exactly one coin");
    bigint(&set[0]["bundle"])
}

/// First-occurrence winner of the one nullifier at the final tip, per the
/// model's own ordered scan of `blocks`.
fn first_winner(state: &Value) -> Option<u64> {
    let tip = bigint(var(state, "tip"));
    let mut blocks: Vec<(u64, &Value)> = var(state, "blocks")["#map"]
        .as_array()
        .expect("#map")
        .iter()
        .map(|pair| (bigint(&pair[0]), &pair[1]))
        .collect();
    blocks.sort_by_key(|(h, _)| *h);
    for (h, content) in blocks {
        if h > tip {
            continue;
        }
        let markers = content["#set"].as_array().expect("#set");
        if let Some(m) = markers.first() {
            assert_eq!(markers.len(), 1, "one marker per block in these traces");
            return Some(bigint(&m["bundle"]));
        }
    }
    None
}

/// Store holding exactly the coin of bundle `b`, as a receiver who accepted it
/// would: state Unspent, lineage attached.
fn store_holding(b: u64) -> (Store, [BabyBear; 8]) {
    let (note, hop) = bundle(b);
    let commitment = note.commitment();
    let mut store = Store::default();
    let key_index = store.allocate_index();
    store
        .insert(Held {
            note,
            key_index,
            lineage: vec![hop],
            state: NoteState::Unspent,
        })
        .expect("fresh store");
    (store, commitment)
}

fn publish_deep(chain: &mut MockChain, b: u64) {
    let (_, hop) = bundle(b);
    chain
        .publish(&Record {
            nullifier: hop.transfer.nullifier,
            bundle_hash: hop.transfer.bundle_hash(),
        })
        .expect("mock publish");
    chain.mine(6);
}

// ---- the conformance tests ----------------------------------------------

/// **`shallow`, replayed for real — then the restore (L2).** The model's
/// non-reconciling wallet keeps a coin whose first occurrence a reorg flipped.
/// The real wallet must quarantine it on the next pass, and must restore it by
/// the full positive check when the original record is re-mined.
#[test]
fn the_real_reconcile_quarantines_the_flip_and_restores_the_remine() {
    let s = last_state("../formal/traces/reorg_shallow.itf.json");
    let held = held_bundle(&s);
    let winner = first_winner(&s).expect("the flip leaves a record on chain");
    assert_ne!(
        held, winner,
        "the shallow counterexample no longer flips first occurrence — \
         the model stopped modelling the reorg it was written for"
    );

    // Acceptance, as it happened pre-reorg: the held bundle's record first and
    // deep, the issuance confirmed. The real `accept` must take it — the model
    // only holds what a conforming receiver accepted.
    let iss = issuance();
    let mut chain = MockChain::new();
    chain.publish_issuance(&iss).expect("mock publish");
    publish_deep(&mut chain, held);
    let (note, hop) = bundle(held);
    let verdict = accept(
        &hiding_config(),
        &chain,
        &TrustAnchor {
            asset: &asset(),
            genesis_commitment: &genesis_note().0.commitment(),
            issued_below: None,
            genesis_amount: VALUE,
        },
        &note,
        &vec![hop.clone()] as &Lineage,
    );
    assert!(
        verdict.is_ok(),
        "pre-reorg acceptance must hold: {verdict:?}"
    );
    let (mut store, commitment) = store_holding(held);

    // The reorg the trace prescribes: the held bundle's record is gone and the
    // competitor's is mined in its place, deep.
    chain.reorg_drop(&hop.transfer.nullifier);
    publish_deep(&mut chain, winner);

    let log = SignLog::default();
    let out = reconcile(&chain, &mut store, &log, Some(&genesis_ref(&iss)));
    assert_eq!(
        out.quarantined.len(),
        1,
        "the coin the shallow wallet keeps must be quarantined by the real pass: {out:?}"
    );
    assert_eq!(
        store.get(&commitment).expect("held").state,
        NoteState::Quarantined,
        "quarantined in the store, not merely reported"
    );

    // L2: the ordinary outcome — the honest record is re-mined. The full
    // positive check must restore the coin, to Unspent.
    chain.reorg_drop(&hop.transfer.nullifier);
    publish_deep(&mut chain, held);
    let out = reconcile(&chain, &mut store, &log, Some(&genesis_ref(&iss)));
    assert_eq!(
        out.restored.len(),
        1,
        "the re-mined coin must be restored by the full positive check: {out:?}"
    );
    assert_eq!(
        store.get(&commitment).expect("held").state,
        NoteState::Unspent,
        "restored to Unspent — whether a spend is in flight is the sign-log's question"
    );
}

/// **`genesisUnchecked`, replayed for real.** A reorg orphans the issuance
/// while the coin's own settlement survives intact. A wallet that re-checks
/// settlement and nothing else keeps the coin — the model violates on exactly
/// that. The real pass must quarantine it on the genesis half alone.
#[test]
fn the_real_reconcile_quarantines_an_orphaned_issuance_even_when_settlement_holds() {
    let s = last_state("../formal/traces/reorg_genesisUnchecked.itf.json");
    let held = held_bundle(&s);
    assert_eq!(
        bigint(var(&s, "genesisAt")),
        0,
        "the counterexample's issuance must be orphaned — else nothing is tested"
    );
    assert_eq!(
        first_winner(&s),
        Some(held),
        "the held coin's own settlement must survive the reorg — that is what \
         makes settlement-only reconciliation blind to this"
    );

    // The post-reorg chain: the spend record first and deep, NO issuance.
    let mut chain = MockChain::new();
    publish_deep(&mut chain, held);
    let (_, hop) = bundle(held);
    match chain.first_occurrence(&hop.transfer.nullifier) {
        Lookup::Found(o) => assert_eq!(
            o.bundle_hash,
            hop.transfer.bundle_hash(),
            "settlement must be perfect, so the quarantine can only be the genesis"
        ),
        other => panic!("the spend record should be on chain: {other:?}"),
    }

    let (mut store, commitment) = store_holding(held);
    let iss = issuance();
    let log = SignLog::default();
    let out = reconcile(&chain, &mut store, &log, Some(&genesis_ref(&iss)));
    assert_eq!(
        out.quarantined.len(),
        1,
        "a coin whose issuance vanished must be quarantined however well its \
         own hops settled: {out:?}"
    );
    assert_eq!(
        store.get(&commitment).expect("held").state,
        NoteState::Quarantined,
    );
}
