//! The WOTS+ verification AIR.
//!
//! One row per hash step. Each row constrains a full Poseidon2 permutation (via
//! the vendored [`crate::poseidon2_eval`]) and carries the chain bookkeeping
//! around it.
//!
//! ## Why no lookups are needed
//!
//! WOTS+ chains have *different lengths* — chain `i` is walked `w-1-d_i` times —
//! so rows are not naturally uniform, which is what first suggested this needed
//! cross-table lookups. It doesn't. Every row permutes unconditionally, keeping
//! those constraints at their natural degree, and a boolean **selector** decides
//! whether the chain value advances:
//!
//! ```text
//! perm_out  = Poseidon2(inputs)                       // unconditional
//! chain_out = sel * perm_out + (1 - sel) * chain_in    // degree 2 on top
//! next.chain_in = chain_out                            // transition
//! ```
//!
//! An inactive row still permutes; its result is simply discarded. That costs
//! rows (67 chains × 15 slots = 1,005 regardless of the digits) and buys a
//! single-AIR design that `p3-uni-stark` can prove as-is.
//!
//! ## What this AIR constrains, and what the verifier wrapper must add
//!
//! In-circuit: every permutation; the selector-gated chain advance; that each
//! chain's walk length equals `W-1-digit`; that `digit` is range-checked to
//! `0..16` by boolean bits and held constant down the chain; that selectors are
//! **non-increasing** within a chain, so a prover cannot scatter the same number
//! of steps to reach a different tip; and — via the public values — that chain
//! `c`'s digit equals `pv[PV_DIGITS + c]` and chain `c`'s final value equals
//! `pv[PV_TIPS + c]` (constraints 13–17).
//!
//! The digits are **not decomposed from the message in-circuit**, deliberately.
//! An in-circuit decomposition would need a canonicity argument (BabyBear's
//! modulus is ~2^31, so a 32-bit decomposition admits both `e` and `e+p`) and an
//! in-circuit sponge to bind it, roughly doubling the trace. Instead the
//! *verifier* computes `wots::digits(msg)` — canonical by construction, since
//! `as_canonical_u32` is a bijection onto `0..p` — and supplies all 67 digits as
//! public values. The prover never supplies a digit; there is nothing for it to
//! choose. The same one-hot machinery pins each chain's tip to a public value.
//!
//! That makes the binding a property of **STARK + wrapper**, and the wrapper's
//! two host-side checks are consensus rules, not conveniences:
//!
//! 1. the public values MUST be `digits(msg) ++ tips`, built by the verifier
//!    from the message it is accepting and the tips the proof carries; and
//! 2. `wots::compress(tips)` MUST equal the public key being verified against.
//!
//! [`crate::prove::verify`] is the only exported entry point and performs both;
//! calling the raw STARK verifier with other public values proves nothing about
//! any message or key. A future recursive verifier must reproduce both checks.
//!
//! **A differential test is necessary and not sufficient.** It shows the circuit
//! agrees with [`crate::wots`] on the cases exercised. It cannot show that no
//! *other* witness satisfies the constraints, which is the property that stops
//! forgery. Under-constrained columns are invisible to honest-witness testing —
//! which is why the negative tests in [`crate::prove`] tamper with each new
//! column family individually.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_RC16_EXTERNAL_FINAL,
    BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_poseidon2_air::{num_cols, Poseidon2Cols};

use crate::poseidon2_eval::{eval_permutation, Constants};
use crate::wots::{CHAINS, LOG_W, N, W, WIDTH};

/// Poseidon2-16 over BabyBear as published: 4+4 full rounds, **13** partial.
///
/// 13, not the 20 in upstream's benchmark examples — `BABYBEAR_RC16_INTERNAL`
/// has 13 entries, and any other count would describe a permutation the host
/// does not compute.
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 13;
pub const SBOX_DEGREE: u64 = 7;
pub const SBOX_REGISTERS: usize = 1;

/// Columns of one Poseidon2 permutation.
pub const P2_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// `[ Poseidon2Cols | chain_in | chain_out | sel | is_last | digit | bits(4) | acc | oh(67) | pos | pinv ]`
///
/// - `chain_in`/`chain_out` — the WOTS+ value before and after this step
/// - `sel` — whether this step is active
/// - `is_last` — marks a chain's final row, so transition constraints do not
///   span chain boundaries
/// - `digit` — the chain's Winternitz digit, held constant down the chain
/// - `bits` — `digit`'s 4-bit decomposition, which range-checks it to `0..16`
///   without a lookup table
/// - `acc` — running count of active steps within the chain
/// - `oh` — one-hot chain-index register: `oh[c] = 1` on every row of chain `c`,
///   all-zero on padding. Fully determined by constraints (pinned first row +
///   deterministic rotation), so the prover has no freedom in it. It is what
///   lets a uniform AIR select "this chain's" public value as a degree-1 sum
///   `Σ_j oh_j · pv_j` instead of an infeasible degree-66 index interpolation.
/// - `pos` — step counter within a chain, cycling `0..=W-2`. Exists to pin
///   `is_last` to actual chain boundaries: without it, `is_last` was merely
///   boolean, and a prover could shift boundaries to re-map chains onto the
///   wrong public digits and tips.
/// - `pinv` — witness inverse of `pos - (W-2)`, zero on boundary rows; the
///   standard inverse trick making `is_last ⇔ pos = W-2` a pair of degree-2
///   constraints.
pub const CHAIN_IN: usize = P2_COLS;
pub const CHAIN_OUT: usize = CHAIN_IN + N;
pub const SEL: usize = CHAIN_OUT + N;
pub const IS_LAST: usize = SEL + 1;
pub const DIGIT: usize = IS_LAST + 1;
pub const BITS: usize = DIGIT + 1;
pub const ACC: usize = BITS + LOG_W;
pub const OH: usize = ACC + 1;
pub const POS: usize = OH + CHAINS;
pub const PINV: usize = POS + 1;
pub const NUM_COLS: usize = PINV + 1;

/// Public-value layout: `[ digits(msg) (67) | tips, chain-major (67×8) ]`.
///
/// Both are the *verifier's* inputs: it computes the digits from the message it
/// is accepting and takes the tips from the proof, then checks
/// `compress(tips) == pk` host-side. See the module docs for why this split is
/// sound and what the wrapper is obligated to do.
pub const PV_DIGITS: usize = 0;
pub const PV_TIPS: usize = PV_DIGITS + CHAINS;
pub const NUM_PUBLIC_VALUES: usize = PV_TIPS + CHAINS * N;

/// Rows per chain: a chain is walked at most `W-1` times.
pub const ROWS_PER_CHAIN: usize = W - 1;
/// Total chain rows for one signature verification.
pub const CHAIN_ROWS: usize = CHAINS * ROWS_PER_CHAIN;

/// The published constants, in the shape the vendored evaluator wants.
pub fn constants() -> Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    Constants {
        beginning_full: BABYBEAR_RC16_EXTERNAL_INITIAL,
        partial: BABYBEAR_RC16_INTERNAL,
        ending_full: BABYBEAR_RC16_EXTERNAL_FINAL,
    }
}

pub struct WotsAir {
    constants: Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

impl Default for WotsAir {
    fn default() -> Self {
        WotsAir {
            constants: constants(),
        }
    }
}

impl<F> BaseAir<F> for WotsAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB: AirBuilderWithPublicValues<F = BabyBear>> Air<AB> for WotsAir {
    fn eval(&self, builder: &mut AB) {
        // The standalone signature circuit has no sponge rows: every row is a
        // chain row or padding, so the gate is identically zero.
        eval_chain_section::<AB>(&self.constants, builder, AB::Expr::ZERO);
    }
}

/// Constraints 1–17: the WOTS+ chain section, shared between [`WotsAir`] and
/// the transfer AIR.
///
/// `sponge_gate` is the caller's "this row is a sponge row" expression —
/// [`WotsAir`] passes zero, the transfer AIR passes its section register's
/// sum. It gates exactly one constraint: 3, the permutation-input wiring,
/// because sponge rows feed the permutation their sponge state instead of
/// `[chain_in | zeros]`. Every other constraint is satisfied on sponge rows
/// by the same inert bookkeeping padding rows already carry (`sel = 0`,
/// `digit = W-1`, zero chain values, the POS cycle), so nothing else needs a
/// gate — and the constraint set stays identical for both circuits, which is
/// the point: one section, one review.
pub(crate) fn eval_chain_section<AB: AirBuilderWithPublicValues<F = BabyBear>>(
    constants: &Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    builder: &mut AB,
    sponge_gate: AB::Expr,
) {
    {
        // Copy the public values out first: `public_values()` borrows the
        // builder, and the assertions below need it mutably.
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&x| x.into()).collect();

        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("empty trace");

        // Borrow the Poseidon2 prefix explicitly: upstream's `Borrow` asserts the
        // slice is exactly one `Poseidon2Cols`, so a narrowed view is required.
        let p2: &Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = local[..P2_COLS].borrow();

        // 1. The permutation itself.
        eval_permutation::<
            AB,
            GenericPoseidon2LinearLayersBabyBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(constants, builder, p2);

        // 1b. The permutation layout's `export` flag, column 0, is pinned.
        //
        //     Upstream's witness generator writes ONE there and upstream's
        //     `eval` never reads it — it exists for a vectorized variant we do
        //     not use. So it was a column a prover could set to anything, on
        //     every row, that nothing checked: 1,024 free field elements sitting
        //     in the middle of a consensus circuit.
        //
        //     Harmless while nothing reads it, which is exactly the argument
        //     that stopped being good enough when a forgery turned up in the
        //     trace height. If a recursive verifier or a lookup argument ever
        //     reads column 0, it would be reading attacker-controlled data.
        //     One constraint removes the question. Pinned to ONE rather than
        //     zero because ONE is what an honest trace contains.
        builder.assert_zero(local[0].clone().into() - AB::Expr::ONE);

        let sel: AB::Expr = local[SEL].clone().into();
        let is_last: AB::Expr = local[IS_LAST].clone().into();

        // 2. Flags are boolean. Without this a prover could use fractional
        //    selectors and interpolate between advancing and not.
        builder.assert_zero(sel.clone() * (sel.clone() - AB::Expr::ONE));
        builder.assert_zero(is_last.clone() * (is_last.clone() - AB::Expr::ONE));

        // 3. The permutation's input is the chain value being stepped, padded
        //    with zeros — matching `wots::step` exactly. Gated off on sponge
        //    rows (the transfer AIR's sponge section wires these inputs to its
        //    running sponge state instead); in the standalone circuit the gate
        //    is zero and this is what it always was.
        let not_sponge = AB::Expr::ONE - sponge_gate;
        for i in 0..N {
            builder.assert_zero(
                not_sponge.clone() * (p2.inputs[i].clone().into() - local[CHAIN_IN + i].clone()),
            );
        }
        for i in N..WIDTH {
            builder.assert_zero(not_sponge.clone() * p2.inputs[i].clone().into());
        }

        // 4. The chain advances only when selected.
        let perm_out = &p2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
        for i in 0..N {
            let out: AB::Expr = local[CHAIN_OUT + i].clone().into();
            let inp: AB::Expr = local[CHAIN_IN + i].clone().into();
            let permuted: AB::Expr = perm_out[i].clone().into();
            builder.assert_eq(
                out,
                sel.clone() * permuted + (AB::Expr::ONE - sel.clone()) * inp,
            );
        }

        // 5. Digit range: the 4 bits are boolean and recompose to `digit`. This is
        //    how `digit` is pinned to 0..16 without a lookup table.
        let mut digit_from_bits = AB::Expr::ZERO;
        for k in 0..LOG_W {
            let b: AB::Expr = local[BITS + k].clone().into();
            builder.assert_zero(b.clone() * (b.clone() - AB::Expr::ONE));
            digit_from_bits += b * AB::Expr::from_u64(1u64 << k);
        }
        builder.assert_eq(local[DIGIT].clone(), digit_from_bits);

        // 6. The running count of active steps. Starts at this row's selector and
        //    accumulates down the chain.
        let acc: AB::Expr = local[ACC].clone().into();

        // 7. On a chain's final row the walk length must match the digit:
        //    verification walks `W-1-digit` steps, so `acc + digit == W-1`.
        //    This is what stops a prover choosing an arbitrary selector pattern.
        builder.assert_zero(
            is_last.clone()
                * (acc.clone() + local[DIGIT].clone().into() - AB::Expr::from_u64((W - 1) as u64)),
        );

        let mut when = builder.when_transition();
        let not_last = AB::Expr::ONE - is_last.clone();

        // 8. Within a chain, this row's output is the next row's input.
        for i in 0..N {
            let carry: AB::Expr = local[CHAIN_OUT + i].clone().into();
            let next_in: AB::Expr = next[CHAIN_IN + i].clone().into();
            when.assert_zero(not_last.clone() * (next_in - carry));
        }

        // 9. `digit` is constant down the chain, so constraint 7's check on the
        //    last row speaks for every row.
        when.assert_zero(
            not_last.clone() * (next[DIGIT].clone().into() - local[DIGIT].clone().into()),
        );

        // 10. Selectors are non-increasing within a chain: once the walk stops it
        //     cannot restart. Without this a prover could scatter the same number
        //     of active steps across the chain and reach a different tip.
        let next_sel: AB::Expr = next[SEL].clone().into();
        when.assert_zero(not_last.clone() * (AB::Expr::ONE - sel.clone()) * next_sel.clone());

        // 11. `acc` accumulates the selectors.
        when.assert_zero(not_last * (next[ACC].clone().into() - acc.clone() - next_sel));

        // 12. A chain's first row starts the count at its own selector. Enforced
        //     on the row *after* a boundary, plus the very first row.
        builder.when_first_row().assert_eq(acc, sel);
        let mut after_last = builder.when_transition();
        after_last
            .assert_zero(is_last.clone() * (next[ACC].clone().into() - next[SEL].clone().into()));

        // ---- Binding to the public values (constraints 13-17) ----
        //
        // Everything below exists so that "chain c" is a fact the constraints
        // establish, not a convention the prover follows. 13-14 pin chain
        // boundaries to absolute positions; 15 turns the pinned boundaries into
        // a one-hot register; 16-17 use the register to select each chain's
        // public digit and tip.

        let pos: AB::Expr = local[POS].clone().into();
        let pinv: AB::Expr = local[PINV].clone().into();
        let last_pos = AB::Expr::from_u64((ROWS_PER_CHAIN - 1) as u64);

        // 13. `pos` counts rows within a chain: 0 on the first row, incrementing,
        //     resetting to 0 after a boundary.
        builder.when_first_row().assert_zero(pos.clone());
        builder.when_transition().assert_zero(
            next[POS].clone().into()
                - (pos.clone() + AB::Expr::ONE) * (AB::Expr::ONE - is_last.clone()),
        );

        // 14. `is_last ⇔ pos = W-2`. Constraint 2 made is_last boolean; nothing
        //     yet pinned WHERE it may be 1. Without this a prover shifts chain
        //     boundaries and re-maps chains onto the wrong public digits/tips.
        //     Forward: is_last = 1 forces pos = W-2. Backward: pos = W-2 makes
        //     the second constraint read 0 = 1 - is_last, forcing is_last = 1;
        //     elsewhere pinv must be the inverse of (pos - (W-2)), which the
        //     honest trace supplies.
        builder.assert_zero(is_last.clone() * (pos.clone() - last_pos.clone()));
        builder.assert_zero(
            (pos.clone() - last_pos.clone()) * pinv - (AB::Expr::ONE - is_last.clone()),
        );

        // 15. The one-hot chain-index register. First row: chain 0. On each
        //     boundary it rotates by one; otherwise it holds. Rotating past
        //     chain 66 leaves it all-zero, and all-zero is a fixed point — that
        //     IS the padding marker, no separate flag. Every value is forced by
        //     induction from the pinned first row, so no booleanity constraint
        //     is needed: the prover has no choice anywhere in this register.
        builder
            .when_first_row()
            .assert_eq(local[OH].clone(), AB::Expr::ONE);
        for j in 1..CHAINS {
            builder.when_first_row().assert_zero(local[OH + j].clone());
        }
        {
            let mut when = builder.when_transition();
            for j in 0..CHAINS {
                let hold = (AB::Expr::ONE - is_last.clone()) * local[OH + j].clone().into();
                let rotate = if j == 0 {
                    AB::Expr::ZERO
                } else {
                    is_last.clone() * local[OH + j - 1].clone().into()
                };
                when.assert_zero(next[OH + j].clone().into() - hold - rotate);
            }
        }

        // 16. Digit binding: on every row of chain c, `digit` equals the public
        //     digit for chain c. The verifier computes those 67 values from the
        //     message with `wots::digits`, so the prover never chooses a digit —
        //     the choice that made forgery possible. Padding rows have an
        //     all-zero register and are vacuous.
        let digit: AB::Expr = local[DIGIT].clone().into();
        let mut digit_sum = AB::Expr::ZERO;
        for j in 0..CHAINS {
            let oh: AB::Expr = local[OH + j].clone().into();
            digit_sum += oh * (digit.clone() - pv[PV_DIGITS + j].clone());
        }
        builder.assert_zero(digit_sum);

        // 17. Tip binding: on chain c's final row, the chain value equals the
        //     public tip for chain c. Together with the wrapper's host-side
        //     `compress(tips) == pk`, this is what binds the proof to a key.
        //     On the padding pseudo-chain's final row the register is all-zero,
        //     so this reads `chain_out = 0` — which padding satisfies.
        for i in 0..N {
            let mut tip = AB::Expr::ZERO;
            for j in 0..CHAINS {
                let oh: AB::Expr = local[OH + j].clone().into();
                tip += oh * pv[PV_TIPS + N * j + i].clone();
            }
            builder.assert_zero(is_last.clone() * (local[CHAIN_OUT + i].clone().into() - tip));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wots;

    #[test]
    fn column_layout_matches_what_was_benchmarked() {
        // Phase A benchmarked 313 columns, but at 20 partial rounds. The published
        // BabyBear permutation has 13, which is 299 columns; chaining adds 18, the
        // digit/selector machinery 6, and the public-value binding another 69
        // (one-hot register + pos + pinv), so the real circuit is 392 — 25% wider
        // than benchmarked, at the same height. Re-measured in spec/04.
        assert_eq!(P2_COLS, 299, "Poseidon2 columns at 13 partial rounds");
        assert_eq!(NUM_COLS, 392);
        assert_eq!(NUM_COLS, P2_COLS + 2 * N + 2 + 1 + LOG_W + 1 + CHAINS + 2);
        assert_eq!(CHAIN_ROWS, 67 * 15);
        assert_eq!(NUM_PUBLIC_VALUES, 603, "67 digits + 67 tips of 8 elements");
    }

    #[test]
    fn constants_match_the_host_permutation() {
        // If these ever diverge the circuit constrains a different function than
        // `wots::step` computes, and every proof fails — or worse, some pass.
        //
        // This used to check the lengths and the *partial* constants only,
        // despite its name. An INITIAL/FINAL swap would have passed it: both
        // external tables are the same shape, so only their contents tell them
        // apart. All three are compared now.
        let c = constants();
        assert_eq!(c.partial.len(), PARTIAL_ROUNDS);
        assert_eq!(c.beginning_full.len(), HALF_FULL_ROUNDS);
        assert_eq!(c.ending_full.len(), HALF_FULL_ROUNDS);
        assert_eq!(c.partial, BABYBEAR_RC16_INTERNAL);
        assert_eq!(c.beginning_full, BABYBEAR_RC16_EXTERNAL_INITIAL);
        assert_eq!(c.ending_full, BABYBEAR_RC16_EXTERNAL_FINAL);
        // The two external tables must not be interchangeable, or the check
        // above proves nothing about ordering.
        assert_ne!(
            BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_EXTERNAL_FINAL,
            "external round constants are identical; an INITIAL/FINAL swap would be undetectable"
        );
    }

    #[test]
    fn host_step_pads_the_way_the_air_constrains() {
        // Constraint 3 asserts inputs[N..WIDTH] are zero. If `wots::step` ever
        // padded differently, honest witnesses would violate the circuit.
        let perm = wots::permutation();
        let x = [BabyBear::ONE; N];
        let out = wots::step(&perm, &x);
        assert_ne!(out, x, "a step must actually permute");
    }
}
