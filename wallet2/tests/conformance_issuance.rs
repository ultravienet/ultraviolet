//! Model ↔ code conformance: the real genesis gate in `accept` must agree with
//! `formal/issuance.qnt`.
//!
//! Second rung of the shared-source-of-truth work (spec/99 `[MODEL-CONFORMANCE]`,
//! SPEC.md §11.3), after `kernel2/tests/conformance_authorization.rs`. The model
//! asks whether supply is countable: under `strict` a receiver takes a coin only
//! if *that issuance's own record* is confirmed on Bitcoin; under `byAmount` — the
//! rule this code shipped first — a receiver is satisfied by *any* record of the
//! same amount, and an attacker mints for free against somebody else's issuance.
//! Those are claims about a *rule*. This test asserts the **real `accept`
//! implements `strict`, not `byAmount`**, by replaying the model's own executions
//! against it:
//!
//!   - every issuance the `strict` trace has a receiver accept must clear the
//!     real genesis gate (its record is on chain, by identity), and
//!   - the free-mint coin the `byAmount` counterexample admits — accepted while
//!     its own record was never published, riding on a same-amount sibling — must
//!     be REFUSED by the real `accept` with `GenesisNotOnChain`.
//!
//! The gap this closes is the exact one that shipped: the free mint was not a
//! design error, it was a translation error — the model matched issuances by
//! identity and the first code matched them by amount, and nothing tied the two
//! together so the drift was invisible. Here the model's frozen counterexample
//! (the committed `.itf.json`) is the test vector, so a code change back to an
//! amount-only check would fail a test derived from the model, not from a human
//! remembering the free mint.
//!
//! **Regenerating the traces** (only when the model changes) is documented in
//! `formal/traces/README.md`; the committed traces are the model as it stood.

use std::collections::{BTreeMap, BTreeSet};

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
use uv_kernel2::transfer::Transfer;
use uv_wallet2::accept::{accept, Hop, Lineage, Rejected, TrustAnchor};
use uv_wallet2::chain::{Chain, MockChain};

// The model's abstract integers, mapped to concrete on-chain values. Assets and
// commitments live in disjoint number ranges so a test can never confuse "asset
// a" with "the genesis note of issuance a" — the two the free mint's cousin
// (asset/commitment transposition) turns on.
fn asset_digest(a: u64) -> Digest {
    [BabyBear::from_u32(0x0001_0000 + a as u32); 8]
}
// Each issuance id is a distinct genesis note. Two issuances of one asset get
// two commitments — which is the whole reason `byAmount` is a hole and `strict`
// is not.
fn commitment_digest(id: u64) -> Digest {
    [BabyBear::from_u32(0x0002_0000 + id as u32); 8]
}

/// One issuance's on-chain record, exactly the three fields the real gate
/// compares.
fn record_for(asset: u64, id: u64, amount: u64) -> Issuance {
    Issuance {
        amount,
        asset: asset_digest(asset),
        commitment: commitment_digest(id),
    }
}

/// A one-hop lineage rooted at issuance `id`'s genesis note. The hop's
/// `input_commitment` must equal the trusted commitment or `accept` refuses at
/// `WrongGenesis` before the supply gate — the gate is what this test is about,
/// so the lineage is built to reach it. The proof is empty: the gate runs before
/// any proof work, so a coin that clears the gate fails later on the proof, and
/// that later failure is the evidence the gate let it through.
fn lineage_from(id: u64) -> (Note, Lineage) {
    let note = Note::build(
        asset_digest(0),
        Amount(1),
        &derive(&WalletSeed([0u8; 32]), id),
    );
    let hop = Hop {
        transfer: Transfer {
            input_commitment: commitment_digest(id),
            nullifier: asset_digest(0),
            outputs: vec![],
            prev_history: history::GENESIS,
        },
        proof: Vec::new(),
    };
    (note, vec![hop])
}

/// Did the real gate refuse this on supply grounds (as opposed to a later,
/// proof/lineage refusal)? The two genesis-gate verdicts are the model's
/// subject; everything else means the gate let the coin through.
fn refused_at_genesis_gate(v: &Result<(), Rejected>) -> bool {
    matches!(
        v,
        Err(Rejected::GenesisNotIssued) | Err(Rejected::GenesisNotOnChain { .. })
    )
}

// ---- ITF trace reading (the model's frozen testimony) -------------------

/// The last state of an ITF trace. `accepted`/`published`/`minted` are all
/// monotonic in these models, so the final state carries the whole execution.
fn last_state(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let v: Value = serde_json::from_str(&raw).expect("itf json");
    v["states"]
        .as_array()
        .and_then(|s| s.last())
        .cloned()
        .expect("a final state")
}

/// The value of the state variable whose name ends with `suffix` (variables are
/// namespaced like `strict::issuance::published`).
fn var<'a>(state: &'a Value, suffix: &str) -> &'a Value {
    state
        .as_object()
        .unwrap()
        .iter()
        .find(|(k, _)| k.ends_with(suffix))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("a `{suffix}` variable"))
}

/// ITF encodes a map as {"#map": [[k, v], ...]} with bigint scalars.
fn as_map(v: &Value) -> BTreeMap<u64, u64> {
    v["#map"]
        .as_array()
        .expect("#map array")
        .iter()
        .map(|pair| (bigint(&pair[0]), bigint(&pair[1])))
        .collect()
}

/// ITF encodes a set as {"#set": [e, ...]}.
fn as_set(v: &Value) -> BTreeSet<u64> {
    v["#set"]
        .as_array()
        .expect("#set array")
        .iter()
        .map(bigint)
        .collect()
}

fn bigint(v: &Value) -> u64 {
    v["#bigint"].as_str().unwrap().parse().unwrap()
}

// ---- the conformance test -----------------------------------------------

/// **The conformance test.** Replay both issuance traces against the real
/// `accept` and require its genesis gate to be `strict`: it clears the coins the
/// sound rule accepts and refuses the free mint the strawman admits.
#[test]
fn the_real_gate_conforms_to_issuance_qnt() {
    let cfg = hiding_config();

    // ---- `strict`: a positive execution. Every accepted issuance has its own
    // record on chain, and the real gate must let each one past. ----
    let s = last_state("../formal/traces/issuance_strict.itf.json");
    let accepted = as_set(var(&s, "accepted"));
    let minted = as_map(var(&s, "minted"));
    let minted_asset = as_map(var(&s, "mintedAsset"));
    let published = as_map(var(&s, "published"));
    let published_asset = as_map(var(&s, "publishedAsset"));
    assert!(
        !accepted.is_empty(),
        "the strict trace accepts nothing — nothing is being checked"
    );

    // The chain as the trace left it: every published issuance's record.
    let mut chain = MockChain::new();
    for (&id, &amount) in &published {
        chain
            .publish_issuance(&record_for(published_asset[&id], id, amount))
            .expect("mock publish");
    }
    for &id in &accepted {
        // The model's own guarantee under strict: an accepted coin's issuance is
        // published. If this ever fails, the trace stopped being a positive one.
        assert!(
            published.contains_key(&id),
            "strict accepted issuance {id} whose record it never published — bad trace"
        );
        let (note, lineage) = lineage_from(id);
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset_digest(minted_asset[&id]),
                genesis_commitment: &commitment_digest(id),
                issued_below: None,
                genesis_amount: minted[&id],
            },
            &note,
            &lineage,
        );
        assert!(
            !refused_at_genesis_gate(&verdict),
            "the model accepts issuance {id} (its record is on chain); the real gate refused it: {verdict:?}"
        );
    }

    // ---- S9: one asset id cannot show two supplies. The trace (seed pinned in
    // `formal/regen-traces.sh`) publishes TWO issuances under one asset, both
    // accepted above through their OWN records — so the per-identity gate has
    // been exercised with same-asset siblings on chain. The sharp edge: a coin
    // under that same asset, with a same-asset AND same-amount record sitting
    // right there, whose *own* commitment has no record — the asset-sibling
    // variant of the free mint — must still be refused. An asset's supply is
    // then the sum of exactly its published records: one asset, one count. ----
    let two_genesis_asset = {
        let mut counts: BTreeMap<u64, u32> = BTreeMap::new();
        for &asset in published_asset.values() {
            *counts.entry(asset).or_insert(0) += 1;
        }
        counts
            .iter()
            .find(|(_, &n)| n >= 2)
            .map(|(&a, _)| a)
            .expect(
                "the strict trace no longer has two issuances under one asset — \
                 S9 is untested; regenerate with the pinned seed",
            )
    };
    let sibling_id = *published_asset
        .iter()
        .find(|(_, &a)| a == two_genesis_asset)
        .map(|(id, _)| id)
        .expect("just counted two");
    // A phantom genesis under the two-genesis asset: an id the trace never
    // published (ids are small; 900 is safely fresh), borrowing a real
    // sibling's amount so the only mismatch is identity.
    let phantom_id: u64 = 900;
    assert!(
        !published.contains_key(&phantom_id),
        "phantom must be fresh"
    );
    let (note, lineage) = lineage_from(phantom_id);
    let verdict = accept(
        &cfg,
        &chain,
        &TrustAnchor {
            asset: &asset_digest(two_genesis_asset),
            genesis_commitment: &commitment_digest(phantom_id),
            issued_below: None,
            genesis_amount: published[&sibling_id],
        },
        &note,
        &lineage,
    );
    assert!(
        matches!(verdict, Err(Rejected::GenesisNotOnChain { .. })),
        "a third genesis under a two-genesis asset, riding its siblings' asset \
         and amount, must be refused by identity — got {verdict:?}"
    );

    // ---- `byAmount`: the free-mint counterexample. A coin was accepted whose
    // own record was never published — it rode on a same-amount sibling. The
    // real gate must refuse it, because the real code matches by identity. ----
    let b = last_state("../formal/traces/issuance_byAmount.itf.json");
    let b_accepted = as_set(var(&b, "accepted"));
    let b_minted = as_map(var(&b, "minted"));
    let b_minted_asset = as_map(var(&b, "mintedAsset"));
    let b_published = as_map(var(&b, "published"));
    let b_published_asset = as_map(var(&b, "publishedAsset"));

    let mut b_chain = MockChain::new();
    for (&id, &amount) in &b_published {
        b_chain
            .publish_issuance(&record_for(b_published_asset[&id], id, amount))
            .expect("mock publish");
    }

    // The free mints: accepted, but their own issuance never reached the chain.
    let free_mints: Vec<u64> = b_accepted
        .iter()
        .copied()
        .filter(|id| !b_published.contains_key(id))
        .collect();
    assert!(
        !free_mints.is_empty(),
        "the byAmount counterexample shows no unpublished-yet-accepted coin — \
         the model stopped modelling the free mint"
    );
    for id in free_mints {
        let amount = b_minted[&id];
        // This is genuinely the free-mint shape: a same-amount record is on
        // chain, which is exactly what the amount-only check would have accepted.
        assert!(
            b_published.values().any(|&a| a == amount),
            "free mint {id} has no same-amount record — not the byAmount attack"
        );
        let (note, lineage) = lineage_from(id);
        let verdict = accept(
            &cfg,
            &b_chain,
            &TrustAnchor {
                asset: &asset_digest(b_minted_asset[&id]),
                genesis_commitment: &commitment_digest(id),
                issued_below: None,
                genesis_amount: amount,
            },
            &note,
            &lineage,
        );
        assert!(
            matches!(verdict, Err(Rejected::GenesisNotOnChain { .. })),
            "byAmount would mint issuance {id} for free against a same-amount record; \
             the REAL gate must refuse it by identity, got {verdict:?}"
        );
    }
}
