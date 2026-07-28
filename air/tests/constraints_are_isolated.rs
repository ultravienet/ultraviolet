//! Tests that isolate one constraint each — written because mutation testing
//! showed the existing negative tests do not.
//!
//! **The finding.** `air/mutants.py` deletes each numbered constraint in turn
//! and asks whether any test notices. Eleven of the seventeen constraints in
//! `wots_air.rs` survived: deleting them changed no test's verdict. That does
//! **not** mean they are redundant. It means no test *isolates* them, so the
//! evidence that each does its job was weaker than the "negative tests per
//! constraint family" claim in `AUDIT-BRIEF.md` implied.
//!
//! **Why the existing tests miss.** They tamper one cell and leave every
//! dependent column stale, so several constraints object at once and any one
//! of them can carry the rejection. Deleting constraints 4 *and* 10 together
//! still left the scattered-selector test passing — constraint 11 caught it,
//! because the `acc` column was never updated to match the swapped selectors.
//! The test proves *something* rejects; it never proved the named constraint
//! does.
//!
//! A second, sharper miss has its own shape: tampering a value that lives in
//! the **public values** changes the Fiat-Shamir transcript, so the proof fails
//! for a reason that has nothing to do with any constraint. A test built that
//! way passes identically against a circuit with the constraint removed.
//!
//! **What an isolating test looks like.** Build a trace that is internally
//! consistent — every dependent column recomputed — and differs from an honest
//! one in exactly the way one constraint forbids. Then only that constraint can
//! object. Each test below is checked by deleting its target and confirming it
//! fails:
//!
//!     python3 air/mutants.py 17
//!
//! Results live in `air/COVERAGE.md`.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use p3_uni_stark::{prove as p3_prove, verify as p3_verify};
use uv_air::prove;
use uv_air::trace;
use uv_air::wots::{self, CHAINS, N};
use uv_air::wots_air::{WotsAir, CHAIN_OUT, IS_LAST, NUM_COLS, PV_TIPS};

fn msg_of(tag: u32) -> wots::Digest {
    let perm = wots::permutation();
    let mut s = [BabyBear::ZERO; wots::WIDTH];
    s[0] = BabyBear::from_u32(tag);
    use p3_symmetric::Permutation;
    perm.permute_mut(&mut s);
    let mut m = [BabyBear::ZERO; N];
    m.copy_from_slice(&s[..N]);
    m
}

/// The public values, built exactly as `prove.rs` builds them.
fn public_values(msg: &wots::Digest, tips: &[wots::Digest; CHAINS]) -> Vec<BabyBear> {
    let mut pv = Vec::new();
    pv.extend(
        wots::digits(msg)
            .iter()
            .map(|&d| BabyBear::from_u32(u32::from(d))),
    );
    for tip in tips {
        pv.extend_from_slice(tip);
    }
    pv
}

/// **Constraint 17 in isolation: the trace's chain endpoints are the public
/// tips.**
///
/// This is the link in the chain of custody that the wrapper's
/// `compress(tips) == owner_pk` step depends on. If the trace can end at one
/// value while the statement declares another, then "the key that signed is the
/// key the note commits to" is unproven and anyone can spend anyone's coin.
///
/// The existing test (`tampered_tips_that_satisfy_the_key_check_are_still_rejected`)
/// modifies `proof.tips` *after* proving. That changes the public values, hence
/// the transcript, so verification fails on Fiat-Shamir before a constraint is
/// consulted — it passes with constraint 17 deleted. This one instead **proves**
/// a trace against public values that disagree with it, which is the thing a
/// forger would actually do, and which only constraint 17 can refuse.
#[test]
fn a_trace_ending_somewhere_other_than_the_declared_tips_is_rejected() {
    let perm = wots::permutation();
    let seed = [71u8; 32];
    let msg = msg_of(31);
    let sig = wots::sign(&perm, &seed, &msg);
    let t = trace::generate(&msg, &sig);

    let honest_tips = trace::tips_from_trace(&t);
    let cfg = prove::config();
    let air = WotsAir::default();

    // Control: the honest trace verifies against its own tips.
    let honest_pv = public_values(&msg, &honest_tips);
    let proof = p3_prove(cfg.inner(), &air, t.clone(), &honest_pv);
    p3_verify(cfg.inner(), &air, &proof, &honest_pv)
        .expect("the control must verify, or this test proves nothing");

    // The forgery: declare a different tip for chain 9 and prove the *same*
    // untouched trace against it. Every other constraint is satisfied — the
    // walk is honest, the digits match, the permutation holds — and the
    // transcript is consistent, because the proof is generated over these
    // public values rather than having them swapped in afterwards.
    let mut lying = honest_tips;
    lying[9][0] += BabyBear::ONE;
    let lying_pv = public_values(&msg, &lying);
    assert_ne!(lying_pv, honest_pv, "the statement must actually differ");

    // A panic inside the prover counts as a rejection: it refused to build the
    // forgery at all, which is the same verdict by a blunter route.
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let p = p3_prove(cfg.inner(), &air, t, &lying_pv);
        p3_verify(cfg.inner(), &air, &p, &lying_pv).is_err()
    }))
    .unwrap_or(true);
    assert!(
        rejected,
        "FORGERY: a trace whose chain ends at one value verified against a \
         statement declaring another. `compress(tips)` then names a key the \
         trace never walked to, and the owner-key check means nothing."
    );
}

/// **Constraint 17's other half: it must bind *every* chain, not just one.**
///
/// Cheap to get wrong — a loop bound off by one, or a gate that stops early,
/// leaves the last chain free. Nothing else in the suite would notice, since
/// every honest trace agrees everywhere.
#[test]
fn every_chain_is_bound_to_its_tip_not_merely_the_first() {
    let perm = wots::permutation();
    let seed = [72u8; 32];
    let msg = msg_of(32);
    let sig = wots::sign(&perm, &seed, &msg);
    let t = trace::generate(&msg, &sig);
    let honest_tips = trace::tips_from_trace(&t);
    let cfg = prove::config();
    let air = WotsAir::default();

    for chain in [0usize, 1, CHAINS / 2, CHAINS - 1] {
        let mut lying = honest_tips;
        lying[chain][0] += BabyBear::ONE;
        let pv = public_values(&msg, &lying);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let p = p3_prove(cfg.inner(), &air, t.clone(), &pv);
            p3_verify(cfg.inner(), &air, &p, &pv).is_err()
        }))
        .unwrap_or(true);
        assert!(rejected, "chain {chain}'s tip is not bound to its trace");
    }
}

/// **The probe's control.** If the harness cannot tell a genuinely free
/// declaration from a bound one, every pass above is vacuous. `PV_TIPS` is
/// where the tips live; this asserts the layout the tests above assume, so a
/// layout change breaks the test rather than silently defanging it.
#[test]
fn the_tests_above_are_perturbing_the_tip_region_they_think_they_are() {
    let perm = wots::permutation();
    let msg = msg_of(33);
    let sig = wots::sign(&perm, &[73u8; 32], &msg);
    let t = trace::generate(&msg, &sig);
    let tips = trace::tips_from_trace(&t);

    let pv = public_values(&msg, &tips);
    assert_eq!(pv.len(), CHAINS + CHAINS * N, "public-value layout changed");
    assert_eq!(
        &pv[PV_TIPS..PV_TIPS + N],
        &tips[0][..],
        "PV_TIPS does not point at the tips"
    );

    // And the trace really does carry chain 0's tip on its final chain row,
    // which is the cell constraint 17 compares against.
    let last_row_of_chain_0 = (0..t.height())
        .find(|&r| t.values[r * NUM_COLS + IS_LAST] == BabyBear::ONE)
        .expect("some row must be a chain boundary");
    assert_eq!(
        &t.values[last_row_of_chain_0 * NUM_COLS + CHAIN_OUT
            ..last_row_of_chain_0 * NUM_COLS + CHAIN_OUT + N],
        &tips[0][..],
        "the trace's first chain endpoint is not tip 0"
    );
    let _ = RowMajorMatrix::new(vec![BabyBear::ZERO; NUM_COLS], NUM_COLS);
}
