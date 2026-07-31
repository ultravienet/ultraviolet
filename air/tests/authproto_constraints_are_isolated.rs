//! Isolating tests for `AuthProtoAir` — the (one) transfer circuit.
//!
//! `authproto_air.rs` is the sole money-path circuit since the signature
//! and signature-verifying transfer circuits were deleted (spec/99
//! `[PROOF-AUTH]`). Its mutation sweep (air/COVERAGE.md) leaves 9 of 16
//! constraints as survivors: no test failed when they were deleted. They are not
//! dead — the sponge and money constraints are byte-identical to the deleted
//! `transfer_air`'s swept-clean 20–32 — the sweep measures *our knowledge*, not
//! the circuit.
//!
//! This file closes the survivors that live in ordinary witness columns, where a
//! single tampered cell can be caught by exactly one constraint. The sponge-lane
//! constraints (4–10, 13) pin **permutation input lanes**: perturbing one also
//! breaks the permutation constraint, so no single constraint isolates the
//! tamper, and they need the structural mock-builder probe instead (evaluate the
//! AIR over a perturbed trace and classify failures by which constraint fired,
//! rather than proving). That port is the remaining work; the survivors are
//! tracked in COVERAGE.
//!
//! **Method.** One honest hop, its real trace, and the real prover/verifier over
//! a trace with one cell changed — a panic in the debug constraint check or a
//! failed verify both count as refusal. Each test is verified by deleting its
//! target and watching the sweep flip it from SURVIVED to killed
//! (`python3 air/mutants.py authproto_air <n>`); a tamper that several
//! constraints object to leaves the target SURVIVED, so the sweep is the check
//! that the isolation is real.

use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{prove as p3_prove, verify as p3_verify};

use uv_air::authproto_air::{
    generate, AuthProtoAir, AMT_IN, HEIGHT, NK, NUM_COLS, NUM_PUBLIC_VALUES, RBITS, T,
};
use uv_air::poseidon2::Digest;
use uv_air::prove::{self, TransferPublics};
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

// The first sponge row (row 0) starts the input-note commitment sponge and is
// where the conservation and range-routing constraints are anchored (`g =
// sp(local, 0)`). The padding rows are everything at or above `SPONGE_ROWS`;
// on them the section register is all zero, so a constraint gated on `sp(row, ·)`
// is inert there — which is what lets a boolean tamper land on constraint 15
// alone.
const RANGE_ROW: usize = 0;
const PADDING_ROW: usize = HEIGHT - 1; // the sole padding row: no sponge, nothing gated reads it

/// One honest hop: input of 100 spent into 60 + 40, built exactly as
/// `bin/measure.rs` builds the circuit's differential witness.
fn honest() -> (TransferWitness, Vec<BabyBear>) {
    let limbs = |v: u64| -> [BabyBear; 4] {
        core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
    };
    let open = |tag: u32, v: u64| -> NoteOpening {
        let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
        NoteOpening {
            amount_limbs: limbs(v),
            anchor: sponge::hash(Domain::SpendAnchor, &nk),
            nullifier_key: nk,
            randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
        }
    };
    let commitment = |o: &NoteOpening, asset: &Digest| {
        let mut p = Vec::new();
        p.extend_from_slice(asset);
        p.extend_from_slice(&o.amount_limbs);
        p.extend_from_slice(&o.anchor);
        p.extend_from_slice(&o.randomness);
        sponge::hash(Domain::Note, &p)
    };
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = open(41, 100);
    let outs = [open(42, 60), open(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);
    let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
    let out0 = commitment(&outs[0], &asset);
    let out1 = commitment(&outs[1], &asset);
    let prev_history = [BabyBear::ZERO; 8];
    let publics =
        TransferPublics::new(input_commitment, nullifier, out0, out1, prev_history, asset);
    let msg = *publics.msg();

    // Public values in the circuit's order: input_commitment, nullifier, out0,
    // out1, prev_history, asset, msg (see `authproto_public_values`).
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for part in [
        &input_commitment,
        &nullifier,
        &out0,
        &out1,
        &prev_history,
        &asset,
        &msg,
    ] {
        pv.extend_from_slice(part);
    }
    assert_eq!(pv.len(), NUM_PUBLIC_VALUES);

    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };
    (witness, pv)
}

/// Prove `trace` against `pv` and report whether the circuit refused it — a
/// panic in the prover's debug constraint check, or a failed verify.
fn refused(trace: RowMajorMatrix<BabyBear>, pv: &[BabyBear]) -> bool {
    let cfg = prove::config();
    let air = AuthProtoAir::default();
    catch_unwind(AssertUnwindSafe(|| {
        let p = p3_prove(cfg.inner(), &air, trace, pv);
        p3_verify(cfg.inner(), &air, &p, pv).is_err()
    }))
    .unwrap_or(true)
}

/// The control every test below depends on: the honest trace verifies, so a
/// rejection means the tamper was caught and not that nothing verifies.
#[test]
fn the_honest_authproto_trace_verifies() {
    let (w, pv) = honest();
    assert!(
        !refused(generate(&w), &pv),
        "the honest proof-native hop must verify, or the tamper tests below prove nothing"
    );
}

/// **Constraint 2 alone: the vendored `export` flag (column 0) is pinned to 1.**
///
/// A padding row is chosen so the permutation is unaffected: its inputs stay
/// zero, so its permutation output is unchanged and constraint 1 has nothing to
/// object to. Only constraint 2 — `local[0] == 1` — reads the flag, so deleting
/// it is what lets the wrong flag through.
#[test]
fn a_wrong_export_flag_is_rejected() {
    let (w, pv) = honest();
    let mut v = generate(&w).values;
    // Column 0 of a padding row is the Poseidon2 `export` flag; a column nothing
    // else reads is a column a prover controls unless 2 pins it.
    v[PADDING_ROW * NUM_COLS] = BabyBear::from_u32(2);
    assert!(
        refused(RowMajorMatrix::new(v, NUM_COLS), &pv),
        "an export flag other than 1 must be refused (constraint 2)"
    );
}

/// **Constraint 15 alone: range bits are boolean.**
///
/// A range bit is set to 2 on a padding row. Constraint 15 checks booleanity on
/// every row; constraint 16 reads the bits only through `sp(local, m)`, which is
/// zero on a padding row, so the range-routing constraint is inert there and
/// only 15 objects.
#[test]
fn a_non_boolean_range_bit_is_rejected() {
    let (w, pv) = honest();
    let mut v = generate(&w).values;
    v[PADDING_ROW * NUM_COLS + RBITS] = BabyBear::from_u32(2);
    assert!(
        refused(RowMajorMatrix::new(v, NUM_COLS), &pv),
        "a range bit that is not 0 or 1 must be refused (constraint 15)"
    );
}

/// **Constraint 16 alone: the range bits recompose to the limb they gate.**
///
/// On the first range row the bits decompose input-amount limb 0. Flipping bit 0
/// keeps every bit boolean (constraint 15 stays satisfied) but makes
/// `Σ bit·2^k` disagree with the limb, which only constraint 16 forbids. The
/// limb, the carries and the conservation columns are untouched, so nothing in
/// the money-arithmetic family objects.
#[test]
fn range_bits_that_disagree_with_their_limb_are_rejected() {
    let (w, pv) = honest();
    let mut v = generate(&w).values;
    // Bit 0 of the range decomposition on the row that routes AMT_IN limb 0.
    let cell = RANGE_ROW * NUM_COLS + RBITS;
    // Flip it, staying boolean: 0 -> 1 or 1 -> 0.
    v[cell] = BabyBear::ONE - v[cell];
    // Guard: the honest limb 0 of amount 100 is 100 (< 2^16), whose bit 0 is 0,
    // so this flip genuinely changes the recomposed sum.
    assert!(
        refused(RowMajorMatrix::new(v, NUM_COLS), &pv),
        "a range decomposition that does not sum to its limb must be refused (constraint 16)"
    );
}

/// **Constraint 4b alone: a padding row carries no witness.**
///
/// The single padding row's `NK`, `T` and amount columns are read by nothing
/// else — every rule that consumes them is gated on `sp(local, ..)`, which is
/// zero there. Before 4b that made them **28 free field elements per proof**, a
/// prover's to choose. Found by the pairwise probe on 2026-07-30 and fixed as
/// the other half of constraint 4's own argument.
///
/// Three cells rather than one, because the finding was that a whole *region*
/// was free and a single-cell test would not distinguish "this cell is pinned"
/// from "this region is".
#[test]
fn witness_columns_on_a_padding_row_are_rejected() {
    for (label, col) in [
        ("nullifier key", NK),
        ("spend anchor", T),
        ("input amount", AMT_IN),
    ] {
        let (w, pv) = honest();
        let mut v = generate(&w).values;
        v[PADDING_ROW * NUM_COLS + col] = BabyBear::from_u32(0xDEAD);
        assert!(
            refused(RowMajorMatrix::new(v, NUM_COLS), &pv),
            "a padding row's {label} column must be zero (constraint 4b); leaving it \
             free is 28 prover-chosen field elements that no rule reads"
        );
    }
}
