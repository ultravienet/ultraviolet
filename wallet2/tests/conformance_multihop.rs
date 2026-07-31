//! Model ↔ code conformance: the real whole-lineage gate in `accept` must agree
//! with `formal/multihop.qnt`.
//!
//! Third rung of the shared-source-of-truth work (spec/99 `[MODEL-CONFORMANCE]`,
//! SPEC.md §11.3), and the one that replays the attack that started the whole
//! formal program: **per-hop first-occurrence checks do not compose.** The model
//! found an 8-step inflation — an attacker double-spends the genesis, loses the
//! race on purpose, walks the losing branch through a second wallet of their own
//! (which checks nothing, unobservably), and pays an honest receiver whose own
//! hop's record is fresh and uncontested. Every check the buggy rule runs
//! passes; one coin becomes two.
//!
//! This test replays the model's own executions against the real `accept`, with
//! **real notes, real transfers, and real proofs per hop** — the earlier rungs
//! could stop at a gate that runs before proof verification; the settlement loop
//! runs after it, so this rung proves each hop like a real payer:
//!
//!   - the coin the `buggy` counterexample's honest receiver was inflated with —
//!     final hop's record won, an ancestor's lost — must be REFUSED by the real
//!     `accept` with `LostRace` at that ancestor, and
//!   - the coin in the same trace whose one-hop ancestry genuinely won, and every
//!     coin the `fixed` trace's honest receivers accept, must be ACCEPTED — the
//!     gate must be the ancestry rule, not merely paranoid.
//!
//! The committed traces (`formal/traces/multihop_*.itf.json`) are the model's
//! frozen testimony; regeneration is a review event, documented in
//! `formal/traces/README.md`.

use std::collections::BTreeMap;

use serde_json::Value;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use uv_air::poseidon2::Digest;
use uv_air::prove::hiding_config;
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::issuance::Issuance;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer_prove::prove_hiding;
use uv_wallet2::accept::{accept, Hop, Lineage, Rejected, TrustAnchor};
use uv_wallet2::chain::{Chain, Lookup, MockChain};

/// The model's honest wallets, verbatim from `multihop.qnt`. A coin held by
/// either is a coin some conforming receiver accepted.
const HONEST: [&str; 2] = ["carol", "dave"];

/// Every model note is a whole-note move of the same value; the concrete
/// amount only has to be consistent and small enough to confirm fast.
const VALUE: u64 = 100;

fn asset() -> Digest {
    [BabyBear::from_u32(0x00A5_0000); 8]
}

/// Model note `n` → a real note. One wallet seed, note id as the key index, so
/// the mapping is deterministic and two spends of one model note become two
/// spends of one real note — which is what makes the race real.
fn note(n: u64) -> (Note, uv_kernel2::keys::NoteKeys) {
    let keys = derive(&WalletSeed([0x33u8; 32]), n);
    (Note::build(asset(), Amount(VALUE), &keys), keys)
}

/// The zero-value change note bundle `b` creates beside its payment — the
/// fixed two-output shape. Distinct seed so it can never collide with a
/// payment note.
fn change_note(b: u64) -> Note {
    Note::build(asset(), Amount(0), &derive(&WalletSeed([0x44u8; 32]), b))
}

// ---- ITF trace reading (the model's frozen testimony) -------------------

#[derive(Clone, Copy, Debug)]
struct ModelBundle {
    id: u64,
    input: u64,
}

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

/// `bundles` is a set of `{ id, input, to }` records.
fn bundles_of(state: &Value) -> BTreeMap<u64, ModelBundle> {
    var(state, "bundles")["#set"]
        .as_array()
        .expect("#set")
        .iter()
        .map(|b| {
            let id = bigint(&b["id"]);
            (
                id,
                ModelBundle {
                    id,
                    input: bigint(&b["input"]),
                },
            )
        })
        .collect()
}

/// `recorded` is a map from nullified note id to the winning bundle id.
fn recorded_of(state: &Value) -> BTreeMap<u64, u64> {
    var(state, "recorded")["#map"]
        .as_array()
        .expect("#map")
        .iter()
        .map(|pair| (bigint(&pair[0]), bigint(&pair[1])))
        .collect()
}

/// The notes honest wallets hold at the end of the trace, genesis excluded.
fn honest_held(state: &Value) -> Vec<u64> {
    var(state, "held")["#map"]
        .as_array()
        .expect("#map")
        .iter()
        .filter(|pair| HONEST.contains(&pair[0].as_str().expect("wallet name")))
        .flat_map(|pair| pair[1]["#set"].as_array().expect("#set").iter().map(bigint))
        .filter(|&n| n != 0)
        .collect()
}

// ---- rebuilding the model's world in the real one -----------------------

/// A bundle's ancestry, genesis-first. In this model a bundle's id IS the note
/// it creates, so the predecessor of `b` is the bundle whose id is `b.input`.
fn chain_to(bundles: &BTreeMap<u64, ModelBundle>, id: u64) -> Vec<ModelBundle> {
    let mut chain = Vec::new();
    let mut cur = bundles[&id];
    loop {
        chain.push(cur);
        if cur.input == 0 {
            break;
        }
        cur = bundles[&cur.input];
    }
    chain.reverse();
    chain
}

/// Build the real transfers + proofs for one note's whole lineage. The history
/// fold is computed exactly as a real payer would: each hop's `prev_history`
/// is the fold of its ancestors' bundle hashes.
fn real_lineage(bundles: &BTreeMap<u64, ModelBundle>, id: u64) -> Lineage {
    let cfg = hiding_config();
    let mut folded = history::GENESIS;
    let mut lineage = Vec::new();
    for b in chain_to(bundles, id) {
        let (input, keys) = note(b.input);
        let (created, _) = note(b.id);
        let (transfer, proof) =
            prove_hiding(&cfg, &input, &keys, [&created, &change_note(b.id)], &folded);
        folded = history::advance(&folded, &transfer.bundle_hash());
        lineage.push(Hop {
            transfer,
            proof: bincode::serialize(&proof).expect("proof serializes"),
        });
    }
    lineage
}

/// The chain as the trace left it: the genesis issuance record, plus exactly
/// the first-occurrence winners the model recorded — including the records of
/// bundles the coin under test is NOT part of, which is what a losing branch
/// loses to.
fn real_chain(bundles: &BTreeMap<u64, ModelBundle>, recorded: &BTreeMap<u64, u64>) -> MockChain {
    let mut chain = MockChain::new();
    chain
        .publish_issuance(&Issuance {
            amount: VALUE,
            asset: asset(),
            commitment: note(0).0.commitment(),
        })
        .expect("mock publish");
    for (&nullified, &winner) in recorded {
        // The winner's real transfer, rebuilt on its own ancestry.
        let winning_hop = real_lineage(bundles, winner)
            .pop()
            .expect("a bundle has at least its own hop");
        let (spent, keys) = note(nullified);
        chain
            .publish(&Record {
                nullifier: uv_kernel2::nullifier::of_note(&spent, &keys.nullifier_key),
                bundle_hash: winning_hop.transfer.bundle_hash(),
            })
            .expect("mock publish");
    }
    chain.mine(10);
    chain
}

fn trust() -> (Digest, Digest) {
    (asset(), note(0).0.commitment())
}

// ---- the conformance tests ----------------------------------------------

/// **The counterexample, replayed for real.** The coin the model's buggy
/// receiver was inflated with must be refused by the real `accept` at exactly
/// the ancestor hop that lost its race — and the honest coin in the same trace
/// must still be accepted, so the refusal is the ancestry rule and not
/// paranoia.
#[test]
fn the_real_gate_refuses_the_inflation_the_buggy_rule_accepts() {
    let s = last_state("../formal/traces/multihop_buggy.itf.json");
    let bundles = bundles_of(&s);
    let recorded = recorded_of(&s);
    let held = honest_held(&s);
    let chain = real_chain(&bundles, &recorded);
    let cfg = hiding_config();
    let (asset, genesis) = trust();

    // Partition what honest wallets hold by what the model knows of each coin's
    // ancestry: a coin is clean iff every ancestor hop won its race.
    let ancestry_wins = |id: u64| {
        chain_to(&bundles, id)
            .iter()
            .all(|b| recorded.get(&b.input) == Some(&b.id))
    };
    let inflated: Vec<u64> = held
        .iter()
        .copied()
        .filter(|&n| !ancestry_wins(n))
        .collect();
    let clean: Vec<u64> = held.iter().copied().filter(|&n| ancestry_wins(n)).collect();
    assert!(
        !inflated.is_empty(),
        "the buggy counterexample shows no honest-held coin with a losing \
         ancestor — the model stopped modelling the inflation"
    );
    assert!(
        !clean.is_empty(),
        "the buggy counterexample no longer contains an honestly-won coin — \
         acceptance would go untested"
    );

    for id in inflated {
        let lineage = real_lineage(&bundles, id);
        // This is genuinely the compositionality attack: the FINAL hop's own
        // record won its race — the per-hop rule is satisfied — and only an
        // ancestor lost. If this stops holding, the trace is a different bug.
        let last = lineage.last().expect("non-empty");
        match chain.first_occurrence(&last.transfer.nullifier) {
            Lookup::Found(o) => assert_eq!(
                o.bundle_hash,
                last.transfer.bundle_hash(),
                "the inflated coin's own hop must have won — that is what makes \
                 per-hop checking blind to it"
            ),
            other => panic!("the final hop's record should be on chain: {other:?}"),
        }
        let losing_hop = chain_to(&bundles, id)
            .iter()
            .position(|b| recorded.get(&b.input) != Some(&b.id))
            .expect("an inflated coin has a losing ancestor");
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &genesis,
                issued_below: None,
                genesis_amount: VALUE,
            },
            &note(id).0,
            &lineage,
        );
        assert!(
            matches!(verdict, Err(Rejected::LostRace(i)) if i == losing_hop),
            "the model's buggy rule accepts coin {id} (final hop won, ancestor \
             {losing_hop} lost); the REAL gate must refuse it at that ancestor, \
             got {verdict:?}"
        );
    }

    for id in clean {
        let lineage = real_lineage(&bundles, id);
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &genesis,
                issued_below: None,
                genesis_amount: VALUE,
            },
            &note(id).0,
            &lineage,
        );
        assert!(
            verdict.is_ok(),
            "coin {id}'s whole ancestry won its races; the real gate refused an \
             honest coin: {verdict:?}"
        );
    }
}

/// **The fixed rule, replayed for real.** Every coin the fixed model's honest
/// receivers accept must clear the real `accept` — the model only lets them
/// accept when the whole ancestry won, and the code must agree that this is
/// sufficient, not just necessary.
#[test]
fn every_coin_the_fixed_model_accepts_clears_the_real_gate() {
    let s = last_state("../formal/traces/multihop_fixed.itf.json");
    let bundles = bundles_of(&s);
    let recorded = recorded_of(&s);
    let held = honest_held(&s);
    assert!(
        !held.is_empty(),
        "the fixed trace accepts nothing — nothing is being checked \
         (regenerate with the pinned seed in formal/regen-traces.sh)"
    );
    let chain = real_chain(&bundles, &recorded);
    let cfg = hiding_config();
    let (asset, genesis) = trust();

    for id in held {
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &genesis,
                issued_below: None,
                genesis_amount: VALUE,
            },
            &note(id).0,
            &real_lineage(&bundles, id),
        );
        assert!(
            verdict.is_ok(),
            "the fixed model accepts coin {id} (its whole ancestry won); the \
             real gate refused it: {verdict:?}"
        );
    }
}
