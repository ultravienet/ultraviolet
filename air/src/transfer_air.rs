//! The transfer AIR: one money-path hop in one table.
//!
//! Rows 0..1004 are the WOTS+ chain section, byte-identical in constraints to
//! [`crate::wots_air`] (the shared [`eval_chain_section`] — one section, one
//! review). Rows 1005..1022 are eighteen sponge rows computing, with the same
//! per-row Poseidon2 permutation:
//!
//! ```text
//! rows 1005..1009  C_in  = sponge(NOTE, asset ‖ amt_in ‖ owner_pk ‖ t ‖ rnd)
//! rows 1010..1011  nf    = sponge(NULL, nk ‖ C_in)
//! rows 1012..1016  C_out0 = sponge(NOTE, asset ‖ amt_0 ‖ …private…)
//! rows 1017..1021  C_out1 = sponge(NOTE, asset ‖ amt_1 ‖ …private…)
//! row  1022        t     = sponge(ANCHOR, nk)      <- the spend anchor
//! ```
//!
//! plus conservation `amt_in = amt_0 + amt_1` over range-checked 16-bit limbs.
//! Row 1023 alone is inert padding. Height stays 1024: the whole hop —
//! signature verification included — costs the same trace as the signature
//! alone, because the sponge work rides in rows the power-of-two padding was
//! already paying for.
//!
//! ## The shape is fixed: two outputs, always
//!
//! A one-output payment is proved as a two-output transfer whose second output
//! is a genuine zero-amount note (fresh keys and randomness, owned by the
//! sender). One uniform trace, no gated "output exists" constraint family —
//! and a privacy improvement, not a cost: output count was public anyway (the
//! commitments are on the record's bundle), and under the fixed shape every
//! hop looks alike, with the dummy indistinguishable from real change.
//! `kernel2::transfer::check_shape` enforces the same rule host-side.
//!
//! ## What the wrapper must add (consensus rules, as in [`crate::wots_air`])
//!
//! The verifier computes `digits(bundle_hash(transfer))` from the *public*
//! transfer it is validating, sets `pv.owner_pk := compress(proof.tips)`
//! (definitional, so the tips→key check cannot be skipped), and fills the
//! remaining public values from the transfer. History advance stays host-side:
//! `prev_history` and the bundle hash are both public, so `advance` needs no
//! circuit. The chain of custody the two halves establish together:
//! tips →(host compress)→ owner_pk →(constraint 25)→ C_in's preimage
//! →(on-chain record)→ the note being spent; and digits →(host)→ bundle hash
//! →(host)→ the exact public transfer.
//!
//! ## Sponge-section registers
//!
//! - `SP[0..17]` — one-hot shift register marking the sponge rows, seeded by
//!   `is_last · oh[66]` (true exactly once, on the last chain row) and shifted
//!   every transition. Fully determined by induction, like `OH`: the prover
//!   has zero freedom in it, so no booleanity constraints are needed.
//! - `NK`, `T`, `AMT_IN`, `AMT_O0`, `AMT_O1` — "bus" columns held constant across
//!   the section, so a value absorbed on one row is provably the same value
//!   used on another (the nullifier key's three appearances; the limbs'
//!   absorb/conserve/range appearances). The bus is what makes "nullifier
//!   from a foreign key" unsatisfiable rather than merely unlikely.
//! - `CARRY[0..3]`, `RBITS[0..16]` — conservation carries and the 16 shared
//!   range-check bit columns (reused across the 12 limb rows; 16 columns
//!   instead of the 192 a one-row layout would need).
//!
//! Private witness values with no constraint on their *content* (input
//! randomness, output owner/nullifier keys and randomness) occupy no dedicated
//! columns at all: a free absorbed lane is simply an unconstrained permutation
//! input on its row. The Poseidon2 input columns ARE the sponge state.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_poseidon2_air::Poseidon2Cols;

use crate::poseidon2_eval::Constants;
use crate::sponge::Domain;
use crate::wots::{CHAINS, N, WIDTH};
use crate::wots_air::{
    constants, eval_chain_section, HALF_FULL_ROUNDS, IS_LAST, OH, P2_COLS, PARTIAL_ROUNDS, PV_TIPS,
    SBOX_DEGREE, SBOX_REGISTERS,
};

/// Amount limbs per value. Mirrors `kernel2::amount::LIMBS`, pinned by
/// `kernel2::amount::tests::the_circuit_agrees_on_how_many_limbs_an_amount_has`
/// — the pin lives there because `air` cannot depend on `kernel2`.
pub const AMOUNT_LIMBS: usize = 4;
/// Sponge rows in the section.
pub const SPONGE_ROWS: usize = 18;
/// Note-commitment preimage length (mirrors `kernel2::note`; pinned by the
/// end-to-end test — a drift makes honest proofs fail, loudly).
pub const NOTE_PREIMAGE: usize = 36;
/// Nullifier preimage length.
pub const NF_PREIMAGE: usize = 16;
/// Spend-anchor preimage length: the nullifier key alone.
pub const ANCHOR_PREIMAGE: usize = 8;

// ---- Column layout: the WOTS+ columns, then the sponge-section registers ----
pub const SP: usize = crate::wots_air::NUM_COLS;
pub const NK: usize = SP + SPONGE_ROWS;
pub const T: usize = NK + N;
pub const AMT_IN: usize = T + N;
pub const AMT_O0: usize = AMT_IN + AMOUNT_LIMBS;
pub const AMT_O1: usize = AMT_O0 + AMOUNT_LIMBS;
pub const CARRY: usize = AMT_O1 + AMOUNT_LIMBS;
pub const RBITS: usize = CARRY + 3;
pub const NUM_COLS: usize = RBITS + 16;

// ---- Public values: the WOTS+ layout, then the transfer's public data ----
pub const PV_INPUT_COMMITMENT: usize = PV_TIPS + CHAINS * N;
pub const PV_NULLIFIER: usize = PV_INPUT_COMMITMENT + N;
pub const PV_OUT0: usize = PV_NULLIFIER + N;
pub const PV_OUT1: usize = PV_OUT0 + N;
/// Not read by any constraint: bound through `digits(bundle_hash)` instead.
/// Present so the public values are the full self-describing statement a
/// future recursive verifier would consume.
pub const PV_PREV_HISTORY: usize = PV_OUT1 + N;
pub const PV_ASSET: usize = PV_PREV_HISTORY + N;
pub const PV_OWNER_PK: usize = PV_ASSET + N;
pub const NUM_PUBLIC_VALUES: usize = PV_OWNER_PK + N;

/// Which sponge rows start a sponge (fresh capacity). Row 17 is the spend
/// anchor, appended last so the first four sponges keep their row numbers.
const STARTS: [usize; 5] = [0, 5, 7, 12, 17];
/// The anchor row: `t = H(nullifier_key)`, one absorb.
const ANCHOR_ROW: usize = 17;
/// Which sponge rows end one, and the pv slot their permutation output pins.
const PINS: [(usize, usize); 4] = [
    (4, PV_INPUT_COMMITMENT),
    (6, PV_NULLIFIER),
    (11, PV_OUT0),
    (16, PV_OUT1),
];

pub struct TransferAir {
    constants: Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

impl Default for TransferAir {
    fn default() -> Self {
        TransferAir {
            constants: constants(),
        }
    }
}

impl<F> BaseAir<F> for TransferAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

type P2<'a, AB> = &'a Poseidon2Cols<
    <AB as AirBuilder>::Var,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

impl<AB: AirBuilderWithPublicValues<F = BabyBear>> Air<AB> for TransferAir {
    fn eval(&self, builder: &mut AB) {
        // Constraints 1-17, shared with WotsAir; the gate frees the sponge
        // rows' permutation inputs from the chain wiring.
        let sponge_gate: AB::Expr = {
            let main = builder.main();
            let local = main.row_slice(0).expect("empty trace");
            (0..SPONGE_ROWS)
                .map(|j| local[SP + j].clone().into())
                .fold(AB::Expr::ZERO, |a, b: AB::Expr| a + b)
        };
        eval_chain_section::<AB>(&self.constants, builder, sponge_gate);

        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&x| x.into()).collect();
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("empty trace");
        let p2_local: P2<AB> = local[..P2_COLS].borrow();
        let p2_next: P2<AB> = next[..P2_COLS].borrow();
        // The permutation output of the local row (the last full round's post
        // state) — the sponge state that the next row continues from.
        let perm_out = &p2_local.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        let sp = |row: &[AB::Var], j: usize| -> AB::Expr { row[SP + j].clone().into() };

        // 18. The section register is empty on the first row.
        for j in 0..SPONGE_ROWS {
            builder.when_first_row().assert_zero(local[SP + j].clone());
        }

        // 19. ...and shifts by one each transition, seeded by the unique
        //     "last row of chain 66" event. Fully determined by induction —
        //     the prover has no freedom anywhere in SP.
        {
            let seed: AB::Expr =
                local[IS_LAST].clone().into() * local[OH + CHAINS - 1].clone().into();
            let mut when = builder.when_transition();
            when.assert_zero(sp(&next, 0) - seed);
            for j in 1..SPONGE_ROWS {
                when.assert_zero(sp(&next, j) - sp(&local, j - 1));
            }
        }

        let start: AB::Expr = STARTS
            .iter()
            .map(|&j| sp(&local, j))
            .fold(AB::Expr::ZERO, |a, b| a + b);
        let note_start = sp(&local, 0) + sp(&local, 7) + sp(&local, 12);
        let null_start = sp(&local, 5);
        let anchor_start = sp(&local, ANCHOR_ROW);

        // 20. A sponge starts with a zeroed capacity (lanes 8..14)...
        for i in N..WIDTH - 2 {
            builder.assert_zero(start.clone() * p2_local.inputs[i].clone().into());
        }

        // 21. ...its input length in lane 14...
        builder.assert_zero(
            note_start.clone()
                * (p2_local.inputs[WIDTH - 2].clone().into()
                    - AB::Expr::from_u64(NOTE_PREIMAGE as u64))
                + null_start.clone()
                    * (p2_local.inputs[WIDTH - 2].clone().into()
                        - AB::Expr::from_u64(NF_PREIMAGE as u64))
                + anchor_start.clone()
                    * (p2_local.inputs[WIDTH - 2].clone().into()
                        - AB::Expr::from_u64(ANCHOR_PREIMAGE as u64)),
        );

        // 22. ...and its domain tag in lane 15 — the same capacity discipline
        //     as `crate::sponge::hash`, row by row.
        builder.assert_zero(
            note_start.clone()
                * (p2_local.inputs[WIDTH - 1].clone().into()
                    - AB::Expr::from_u32(Domain::Note as u32))
                + null_start.clone()
                    * (p2_local.inputs[WIDTH - 1].clone().into()
                        - AB::Expr::from_u32(Domain::Nullifier as u32))
                + anchor_start.clone()
                    * (p2_local.inputs[WIDTH - 1].clone().into()
                        - AB::Expr::from_u32(Domain::SpendAnchor as u32)),
        );

        // 23. A start row's rate is its first chunk (add-absorb into a zero
        //     rate): the shared public asset for the three note commitments —
        //     which IS the asset-continuity rule — and the nullifier key bus
        //     for the nullifier sponge.
        for i in 0..N {
            builder.assert_zero(
                note_start.clone() * (p2_local.inputs[i].clone().into() - pv[PV_ASSET + i].clone())
                    + (null_start.clone() + anchor_start.clone())
                        * (p2_local.inputs[i].clone().into() - local[NK + i].clone().into()),
            );
        }

        // 24. On continuing rows the capacity carries through untouched:
        //     next state = this row's permutation output in lanes 8..16.
        {
            let cont_next: AB::Expr = (0..SPONGE_ROWS)
                .filter(|j| !STARTS.contains(j))
                .map(|j| sp(&next, j))
                .fold(AB::Expr::ZERO, |a, b| a + b);
            let mut when = builder.when_transition();
            for (i, out) in perm_out.iter().enumerate().take(WIDTH).skip(N) {
                when.assert_zero(
                    cont_next.clone() * (p2_next.inputs[i].clone().into() - out.clone().into()),
                );
            }
        }

        // 25. Rate carry + absorb injection on continuing rows: the next
        //     state's rate is this row's permutation output plus what that row
        //     absorbs. Tied lanes get their absorbed value pinned (to a public
        //     value or a bus column); FREE lanes get no term — the witness
        //     lives directly in the permutation input. The zero ties on each
        //     note sponge's final chunk (lanes 4..8) are load-bearing: without
        //     them a prover absorbs four extra free elements under an
        //     unchanged length tag, and the sponge is no longer the host's.
        {
            let zero = AB::Expr::ZERO;
            // (row j, lane i) -> Some(absorbed value); None = free lane.
            let tie = |j: usize, i: usize, next: &[AB::Var]| -> Option<AB::Expr> {
                match j {
                    // C_in chunk 1: amt_in[0..4] ‖ owner_pk[0..4]
                    1 if i < 4 => Some(next[AMT_IN + i].clone().into()),
                    1 => Some(pv[PV_OWNER_PK + (i - 4)].clone()),
                    // C_in chunk 2: owner_pk[4..8] ‖ anchor[0..4]
                    2 if i < 4 => Some(pv[PV_OWNER_PK + 4 + i].clone()),
                    2 => Some(next[T + (i - 4)].clone().into()),
                    // C_in chunk 3: anchor[4..8] ‖ rnd[0..4] (free)
                    3 if i < 4 => Some(next[T + 4 + i].clone().into()),
                    3 => None,
                    // C_in chunk 4: rnd[4..8] (free) ‖ nothing absorbed
                    4 if i < 4 => None,
                    4 => Some(zero.clone()),
                    // nf chunk 1: the input commitment, all 8 lanes
                    6 => Some(pv[PV_INPUT_COMMITMENT + i].clone()),
                    // out0 chunk 1: amt_o0 ‖ owner_pk' (free)
                    8 if i < 4 => Some(next[AMT_O0 + i].clone().into()),
                    8 => None,
                    // out0/out1 middle chunks: all private, all free
                    9 | 10 | 14 | 15 => None,
                    // note-sponge final chunks: rnd (free) ‖ nothing
                    11 | 16 if i < 4 => None,
                    11 | 16 => Some(zero.clone()),
                    // out1 chunk 1: amt_o1 ‖ owner_pk'' (free)
                    13 if i < 4 => Some(next[AMT_O1 + i].clone().into()),
                    13 => None,
                    _ => unreachable!("start rows are not continuing rows"),
                }
            };
            let mut when = builder.when_transition();
            for (i, out) in perm_out.iter().enumerate().take(N) {
                let mut sum = AB::Expr::ZERO;
                for j in (0..SPONGE_ROWS).filter(|j| !STARTS.contains(j)) {
                    if let Some(absorbed) = tie(j, i, &next) {
                        sum += sp(&next, j)
                            * (p2_next.inputs[i].clone().into() - out.clone().into() - absorbed);
                    }
                }
                when.assert_zero(sum);
            }
        }

        // 26. Each sponge's final permutation output is the public digest it
        //     claims: C_in, nf, out0, out1. With 25's row-6 tie this also
        //     closes the loop between the two halves — the commitment absorbed
        //     into the nullifier is the same pv the commitment sponge pinned.
        for (i, out) in perm_out.iter().enumerate().take(N) {
            let mut sum = AB::Expr::ZERO;
            for &(j, slot) in PINS.iter() {
                sum += sp(&local, j) * (out.clone().into() - pv[slot + i].clone());
            }
            builder.assert_zero(sum);
        }

        // 32. The spend anchor. The anchor row hashes the nullifier key, and
        //     its output must equal the `T` bus — which constraint 25 absorbs
        //     into the input commitment. So the spender is forced to know a
        //     preimage of the anchor the note committed to.
        //
        //     This is the constraint that makes non-interactive addressing
        //     possible over hash-based keys, and it closes a live privacy leak.
        //     A payer builds the note from public material only: it knows the
        //     anchor `t`, never the key `nk`. Before this, the note committed
        //     to `nk` itself, so whoever built the note could compute its
        //     nullifier and watch forever for the moment it was spent.
        for (i, out) in perm_out.iter().enumerate().take(N) {
            builder.assert_zero(
                sp(&local, ANCHOR_ROW) * (out.clone().into() - local[T + i].clone().into()),
            );
        }

        // 27. Bus constancy: the nullifier key and the twelve amount limbs are
        //     the same values on every row of the section. Gated on rows
        //     0..16 of the section so the constraint never reaches padding.
        //     (Gating on `is_sponge(local)·is_sponge(next)` would be degree 4;
        //     this gate is degree 1 and equivalent.)
        {
            let not_last_sponge: AB::Expr = (0..SPONGE_ROWS - 1)
                .map(|j| sp(&local, j))
                .fold(AB::Expr::ZERO, |a, b| a + b);
            let mut when = builder.when_transition();
            for col in (NK..NK + 2 * N).chain(AMT_IN..AMT_IN + 3 * AMOUNT_LIMBS) {
                when.assert_zero(
                    not_last_sponge.clone()
                        * (next[col].clone().into() - local[col].clone().into()),
                );
            }
        }

        // 28. Conservation, exact over u64: limb-wise with boolean carries.
        //     With every limb 16-bit-checked (31) and carries boolean (29),
        //     these four equations are u64 equality — no minting, no burning,
        //     no wrap. Checked on the section's first row; the bus makes the
        //     limbs there the same ones the sponges absorbed.
        {
            let g = sp(&local, 0);
            let two16 = AB::Expr::from_u64(1 << 16);
            let limb = |base: usize, k: usize| -> AB::Expr { local[base + k].clone().into() };
            let carry = |k: usize| -> AB::Expr { local[CARRY + k].clone().into() };
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 0) + limb(AMT_O1, 0)
                        - limb(AMT_IN, 0)
                        - two16.clone() * carry(0)),
            );
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 1) + limb(AMT_O1, 1) + carry(0)
                        - limb(AMT_IN, 1)
                        - two16.clone() * carry(1)),
            );
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 2) + limb(AMT_O1, 2) + carry(1)
                        - limb(AMT_IN, 2)
                        - two16.clone() * carry(2)),
            );
            builder
                .assert_zero(g * (limb(AMT_O0, 3) + limb(AMT_O1, 3) + carry(2) - limb(AMT_IN, 3)));
        }

        // 29. Carries are boolean (everywhere; zero elsewhere is boolean).
        for k in 0..3 {
            let c: AB::Expr = local[CARRY + k].clone().into();
            builder.assert_zero(c.clone() * (c - AB::Expr::ONE));
        }

        // 30. Range bits are boolean.
        for k in 0..16 {
            let b: AB::Expr = local[RBITS + k].clone().into();
            builder.assert_zero(b.clone() * (b - AB::Expr::ONE));
        }

        // 31. Limb range routing: on the section's row m (m = 0..12), the 16
        //     shared bit columns recompose to the m-th amount limb. With 30,
        //     every limb is pinned to [0, 2^16) — which is what makes 28's
        //     carry algebra exact and kills the `limb = 2^16` alias.
        {
            let bits_sum: AB::Expr = (0..16)
                .map(|k| local[RBITS + k].clone().into() * AB::Expr::from_u64(1 << k))
                .fold(AB::Expr::ZERO, |a, b: AB::Expr| a + b);
            let mut sum = AB::Expr::ZERO;
            for m in 0..3 * AMOUNT_LIMBS {
                let limb: AB::Expr = local[AMT_IN + m].clone().into();
                sum += sp(&local, m) * (bits_sum.clone() - limb);
            }
            builder.assert_zero(sum);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_consistent() {
        assert_eq!(NUM_COLS, 457);
        assert_eq!(NUM_PUBLIC_VALUES, 659);
        assert_eq!(SP, 392);
        // AMT_IN, AMT_O0, AMT_O1 must be contiguous: constraints 27 and 31
        // iterate them as one 12-limb range.
        // NK and T must be adjacent: constraint 27 holds them constant as one
        // contiguous 2N range.
        assert_eq!(T, NK + N);
        assert_eq!(AMT_O0, AMT_IN + AMOUNT_LIMBS);
        assert_eq!(AMT_O1, AMT_O0 + AMOUNT_LIMBS);
        // The five sponges tile the eighteen rows exactly, and the whole
        // section still fits under the power-of-two trace height with one row
        // to spare — which is why the anchor was free.
        assert_eq!(
            NOTE_PREIMAGE.div_ceil(N) * 3 + NF_PREIMAGE.div_ceil(N) + ANCHOR_PREIMAGE.div_ceil(N),
            SPONGE_ROWS
        );
        const { assert!(crate::wots_air::CHAIN_ROWS + SPONGE_ROWS <= 1024) };
    }
}
