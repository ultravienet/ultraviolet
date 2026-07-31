//! Model ↔ code conformance: the real spend path must agree with
//! `formal/authorization.qnt`.
//!
//! This is the first rung of the shared-source-of-truth work (spec/99
//! `[MODEL-CONFORMANCE]`, SPEC.md §11.3). The model proves that under the sound
//! rule (`enforced`) only a note's owner can spend it, and that the unsafe
//! strawman (`anchorOnly`) lets a forger in. Those are claims about a *rule*.
//! This test asserts the **real proof-native circuit implements that rule** by
//! replaying the model's own executions against `verify_hiding`:
//!
//!   - every spend the `enforced` trace attributes to the owner must VERIFY
//!     (the owner holds the anchor preimage), and
//!   - the spend the `anchorOnly` trace attributes to the forger must be
//!     REFUSED (the forger does not) — i.e. the real code is not the strawman.
//!
//! The gap this closes is the free-mint gap: a model and a code that each look
//! complete while disagreeing. Here the model's frozen testimony (the committed
//! `.itf.json` traces) is the test vector, so a code change that let a forger
//! spend would fail a test derived from the model, not from a human remembering
//! to write it.
//!
//! **Regenerating the traces** (only when the model changes) is documented in
//! `formal/traces/README.md`; the committed traces are the model as it stood.

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::Value;

use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::keys::{derive, NoteKeys, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::transfer_prove::{prove_hiding, verify_hiding};

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use uv_air::poseidon2::Digest;

// The model's abstract parties, mapped to concrete wallet seeds. Every note is
// owned by `OWNER`; `FORGER` never legitimately owns one, which is the whole
// point of the authorization question.
const OWNER_SEED: [u8; 32] = [7u8; 32];
const FORGER_SEED: [u8; 32] = [99u8; 32];
const PAYEE_SEED: [u8; 32] = [8u8; 32];

fn asset() -> Digest {
    [BabyBear::from_u32(0xC0FFEE); 8]
}

/// The owner's real note for model note `n`, and its keys.
fn owner_note(n: u64) -> (Note, NoteKeys) {
    let keys = derive(&WalletSeed(OWNER_SEED), n);
    (Note::build(asset(), Amount(100), &keys), keys)
}

/// Replay: the owner spending note `n` must verify on the real circuit — the
/// owner holds the anchor preimage, which is what `enforced` asserts.
fn assert_owner_can_spend(n: u64) {
    let (input, keys) = owner_note(n);
    let pay = Note::build(asset(), Amount(60), &derive(&WalletSeed(PAYEE_SEED), n));
    let chg = Note::build(
        asset(),
        Amount(40),
        &derive(&WalletSeed(OWNER_SEED), 1000 + n),
    );

    let cfg = uv_air::prove::hiding_config();
    let (transfer, proof) = prove_hiding(&cfg, &input, &keys, [&pay, &chg], &history::GENESIS);
    verify_hiding(&cfg, &proof, &transfer, &asset()).unwrap_or_else(|e| {
        panic!("the model says the owner spends note {n}; the real circuit refused it: {e:?}")
    });
}

/// Replay: the forger spending note `n` — which the *strawman* permits — must
/// be REFUSED by the real circuit. The forger holds a different key, so it
/// cannot exhibit the preimage of the owner's committed anchor: either it
/// cannot even assemble a well-formed spend (a panic on the anchor check) or it
/// assembles one that does not verify. Silently verifying is the one
/// unacceptable outcome — it would mean the real code is the strawman.
fn assert_forger_cannot_spend(n: u64) {
    let (input, _owner_keys) = owner_note(n);
    let forger_keys = derive(&WalletSeed(FORGER_SEED), n);
    let pay = Note::build(asset(), Amount(60), &derive(&WalletSeed(PAYEE_SEED), n));
    let chg = Note::build(
        asset(),
        Amount(40),
        &derive(&WalletSeed(FORGER_SEED), 2000 + n),
    );

    let cfg = uv_air::prove::hiding_config();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // The forger presents the owner's note but its own keys — it does not
        // know the anchor's preimage.
        let (transfer, proof) =
            prove_hiding(&cfg, &input, &forger_keys, [&pay, &chg], &history::GENESIS);
        verify_hiding(&cfg, &proof, &transfer, &asset())
    }));
    match outcome {
        Err(_) => {}     // could not even assemble a spend — refused
        Ok(Err(_)) => {} // assembled, but the proof does not verify — refused
        Ok(Ok(())) => {
            panic!(
                "the strawman lets the forger spend note {n}; the REAL circuit must not, but did"
            )
        }
    }
}

/// Load an ITF trace and return, per state, the set of notes each party has
/// spent.
fn spent_per_state(path: &str) -> Vec<Vec<(String, Vec<u64>)>> {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let v: Value = serde_json::from_str(&raw).expect("itf json");
    let states = v["states"].as_array().expect("states array");
    let mut out = Vec::new();
    for st in states {
        let map = st
            .as_object()
            .unwrap()
            .iter()
            .find(|(k, _)| k.ends_with("spent"))
            .map(|(_, v)| v)
            .expect("a `spent` variable");
        // ITF encodes a map as {"#map": [[key, value], ...]}.
        let mut per_party = Vec::new();
        for pair in map["#map"].as_array().expect("#map array") {
            let party = pair[0].as_str().expect("party string").to_string();
            let set = pair[1]["#set"].as_array().expect("#set array");
            let notes: Vec<u64> = set
                .iter()
                .map(|e| e["#bigint"].as_str().unwrap().parse().unwrap())
                .collect();
            per_party.push((party, notes));
        }
        out.push(per_party);
    }
    out
}

/// The newly-spent (party, note) pairs across a trace — each spend once.
fn new_spends(states: &[Vec<(String, Vec<u64>)>]) -> Vec<(String, u64)> {
    let mut seen: std::collections::BTreeSet<(String, u64)> = Default::default();
    let mut spends = Vec::new();
    for state in states {
        for (party, notes) in state {
            for &n in notes {
                let key = (party.clone(), n);
                if seen.insert(key.clone()) {
                    spends.push(key);
                }
            }
        }
    }
    spends
}

/// **The conformance test.** Replay both traces against the real circuit and
/// require it to agree with the sound rule on every spend the model performed.
#[test]
fn the_real_circuit_conforms_to_authorization_qnt() {
    // `enforced`: a positive execution. Every spend is the owner's, and every
    // one must verify on the real circuit.
    let enforced = spent_per_state("../formal/traces/authorization_enforced.itf.json");
    let enforced_spends = new_spends(&enforced);
    assert!(
        !enforced_spends.is_empty(),
        "the enforced trace performs no spends — nothing is being checked"
    );
    for (party, n) in &enforced_spends {
        assert_eq!(
            party, "owner",
            "the enforced rule must never let the forger spend"
        );
        assert_owner_can_spend(*n);
    }

    // `anchorOnly`: the strawman's counterexample. Its forger-spend must be
    // refused by the real circuit — the real code is `enforced`, not the
    // strawman.
    let anchor_only = spent_per_state("../formal/traces/authorization_anchorOnly.itf.json");
    let forger_spends: Vec<u64> = new_spends(&anchor_only)
        .into_iter()
        .filter(|(p, _)| p == "forger")
        .map(|(_, n)| n)
        .collect();
    assert!(
        !forger_spends.is_empty(),
        "the anchorOnly counterexample shows no forger spend — the model stopped modelling the attack"
    );
    for n in forger_spends {
        assert_forger_cannot_spend(n);
    }
}
