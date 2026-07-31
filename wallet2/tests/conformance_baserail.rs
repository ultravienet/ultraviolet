//! Model ↔ code conformance: the real send path must realize the payment
//! schedule `formal/baserail.qnt` proves possible.
//!
//! Fifth rung of the shared-source-of-truth work (spec/99 `[MODEL-CONFORMANCE]`,
//! SPEC.md §11.3), and the first **liveness** rung. `baserail.qnt`'s
//! `splitPayment` module proves the payment shape the protocol leans on once
//! `noMerge` is accepted: a wallet owing TARGET=2 while holding two notes of 1
//! completes the payment as two part-payments, each settling independently —
//! `paymentRemainsPossible` holds along the way and `delivered` reaches the
//! target. That is a claim that a *schedule exists*. This test replays the
//! frozen schedule against the real machinery and requires it to complete:
//! two `prepare`/`broadcast` calls through the real wallet, real proofs, real
//! records confirming on the chain, and the payee's real `accept` taking both
//! parts — delivered value summing to the model's TARGET.
//!
//! A liveness tie fails differently from a safety tie: there is no rule to
//! weaken and watch refuse, because the failure mode is the send path
//! *refusing a fundable part-payment* or the payee refusing an honestly
//! settled one — which is exactly what this test detects directly. The trace
//! guards assert the model still completes the payment (`delivered == TARGET`,
//! both parts settled), so a regenerated trace that stops paying fails here
//! rather than silently testing nothing.
//!
//! The committed trace (`formal/traces/baserail_splitPayment.itf.json`, seed
//! pinned in `formal/regen-traces.sh`) is the model's frozen testimony;
//! regeneration is a review event (`formal/traces/README.md`).

use serde_json::Value;

use p3_baby_bear::BabyBear;

use uv_air::poseidon2::Digest;
use uv_air::prove::hiding_config;
use uv_kernel2::amount::Amount;
use uv_kernel2::issuance::Issuance;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_wallet2::accept::{accept, Lineage, TrustAnchor};
use uv_wallet2::chain::{Chain, MockChain};
use uv_wallet2::send::{broadcast, prepare, Recipient, WalletCtx};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

const ASSET: Digest = [BabyBear::new(0x00B5_0000); 8];
/// The model: two notes worth 1 each, owing TARGET = 2.
const NOTE_VALUE: u64 = 1;
const TARGET: u64 = 2;

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

// ---- the conformance test ------------------------------------------------

/// **The split payment, realized.** The model's completed schedule — two
/// part-payments of 1, both settled, delivered = 2 — must complete through the
/// real wallet end to end.
#[test]
fn the_real_send_path_completes_the_split_payment_the_model_proves_possible() {
    // The model's own guarantee first: the frozen trace completes the payment.
    let s = last_state("../formal/traces/baserail_splitPayment.itf.json");
    assert_eq!(
        bigint(var(&s, "delivered")),
        TARGET,
        "the splitPayment trace no longer completes the payment — regenerate \
         with the pinned seed, and if it still fails, the model changed"
    );
    let settled = var(&s, "settledIds")["#set"]
        .as_array()
        .expect("#set")
        .len();
    assert_eq!(settled, 2, "both part-payments must settle in the trace");

    // The payer, funded exactly as the model is: two notes of 1.
    let payer = WalletSeed([0x11u8; 32]);
    let payee = WalletSeed([0x22u8; 32]);
    let cfg = hiding_config();
    let mut store = Store::default();
    let mut log = SignLog::default();
    let mut chain = MockChain::new();

    let mut genesis = Vec::new();
    for _ in 0..2 {
        let key_index = store.allocate_index();
        let note = Note::build(ASSET, Amount(NOTE_VALUE), &derive(&payer, key_index));
        // Each note is its own genesis, its issuance on chain — the real
        // `accept` counts supply, so the model's "notes the wallet holds"
        // become notes a receiver could actually take.
        chain
            .publish_issuance(&Issuance {
                amount: NOTE_VALUE,
                asset: ASSET,
                commitment: note.commitment(),
            })
            .expect("mock publish");
        genesis.push(note.commitment());
        store
            .insert(Held {
                note,
                key_index,
                lineage: Lineage::new(),
                state: NoteState::Unspent,
            })
            .expect("fresh store");
    }
    chain.mine(6);

    // The schedule: one part-payment per note, each to its own payee slot,
    // each broadcast and confirmed before the payee validates it.
    let mut delivered = 0u64;
    for (slot, commitment) in genesis.iter().enumerate() {
        let recipient_keys = derive(&payee, slot as u64);
        let prepared = prepare(
            &cfg,
            WalletCtx {
                store: &mut store,
                log: &mut log,
                seed: &payer,
            },
            commitment,
            &Recipient {
                nullifier_anchor: recipient_keys.anchor,
                randomness: recipient_keys.randomness,
            },
            Amount(NOTE_VALUE),
        )
        .unwrap_or_else(|e| panic!("part-payment {slot} must be fundable: {e:?}"));
        let sent = broadcast(&mut chain, prepared, || Ok::<(), String>(()))
            .expect("part-payment publishes");
        assert!(!sent.replayed, "a fresh part-payment is not a replay");
        chain.mine(6);

        // The payee's side, for real: their note, the mailed hop, the genesis
        // anchor for this part — the whole acceptance.
        let payee_note = Note::build(ASSET, Amount(NOTE_VALUE), &recipient_keys);
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &ASSET,
                genesis_commitment: commitment,
                issued_below: None,
                genesis_amount: NOTE_VALUE,
            },
            &payee_note,
            &vec![sent.hop.clone()] as &Lineage,
        );
        assert!(
            verdict.is_ok(),
            "the model settles part-payment {slot}; the real payee refused it: {verdict:?}"
        );
        delivered += NOTE_VALUE;
    }

    assert_eq!(
        delivered, TARGET,
        "the schedule the model proves possible must deliver the target for real"
    );
}
