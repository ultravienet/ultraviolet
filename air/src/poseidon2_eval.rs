//! Poseidon2 permutation constraints — **vendored**, and consensus-critical.
//!
//! ## Why this file exists rather than a dependency
//!
//! `p3-poseidon2-air` implements exactly these constraints, but they are not
//! reachable from outside that crate:
//!
//! - its `eval` is `pub(crate)`, and
//! - its `Borrow<Poseidon2Cols> for [T]` asserts the slice is **exactly one**
//!   `Poseidon2Cols`, so a wider row (ours carries WOTS+ chaining columns
//!   alongside) cannot borrow the Poseidon2 part.
//!
//! So the published AIR is usable whole or not at all, and we need it composed.
//! The round evaluation below is therefore copied from `p3-poseidon2-air` 0.4.3
//! (`src/air.rs`), Plonky3, dual MIT/Apache-2.0. This crate is MIT, which that
//! dual licence permits.
//! Structure and semantics are preserved deliberately: divergence here would be
//! a soundness bug, so this file should be diffed against upstream on any bump,
//! not rewritten.
//!
//! ## What "consensus-critical" means here
//!
//! These constraints decide whether a spend authorization is valid. An
//! **under-constrained** column — one a prover can set freely — lets an attacker
//! satisfy the circuit without knowing a secret, which in a payment system means
//! forging money. That failure mode is invisible to any test that only checks
//! honest witnesses.
//!
//! The differential tests in [`crate::wots_air`] are therefore necessary and
//! **not sufficient**: they establish that the circuit agrees with
//! [`crate::wots`] on the cases exercised, not that no *other* witness satisfies
//! it. Soundness needs external review before this holds value. Said plainly
//! because the temptation is to read a green test suite as more than it is.

use p3_air::AirBuilder;
use p3_baby_bear::{
    BabyBear, BABYBEAR_RC16_EXTERNAL_FINAL, BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{num_cols, FullRound, PartialRound, Poseidon2Cols, SBox};

use crate::wots::WIDTH;

// ---- Poseidon2 parameters, shared by every circuit that permutes ----
//
// These fix the permutation the host computes. `PARTIAL_ROUNDS = 13` because
// the published internal-constant table (`BABYBEAR_RC16_INTERNAL`) has 13
// entries; any other count describes a permutation the host does not compute.
// They lived in `wots_air` when the signature circuit was the only one; they
// moved here, their natural home, when it was removed from the money path.
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 13;
pub const SBOX_DEGREE: u64 = 7;
pub const SBOX_REGISTERS: usize = 1;

/// Columns of one Poseidon2 permutation.
pub const P2_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// The published constants, in the shape the vendored evaluator wants. Host and
/// circuit must agree exactly, so these are `p3-baby-bear`'s published tables —
/// the same ones `default_babybear_poseidon2_16()` uses on the host.
pub fn constants() -> Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    Constants {
        beginning_full: BABYBEAR_RC16_EXTERNAL_INITIAL,
        partial: BABYBEAR_RC16_INTERNAL,
        ending_full: BABYBEAR_RC16_EXTERNAL_FINAL,
    }
}

/// Round constants, owned by us.
///
/// Upstream's `RoundConstants` and `Poseidon2Air::constants` both have
/// `pub(crate)` fields, so a vendored evaluator cannot read them — which means
/// owning the constants is forced, not a preference.
///
/// **Host and circuit must agree exactly**, so these are built from
/// `p3-baby-bear`'s published tables (`BABYBEAR_RC16_*`), the same ones
/// `default_babybear_poseidon2_16()` uses on the host. Note that fixes
/// `PARTIAL_ROUNDS = 13`: the published internal-constant table has 13 entries,
/// so the 20 used in upstream's benchmark examples would not correspond to any
/// real permutation.
pub struct Constants<
    F,
    const WIDTH: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    pub beginning_full: [[F; WIDTH]; HALF_FULL_ROUNDS],
    pub partial: [F; PARTIAL_ROUNDS],
    pub ending_full: [[F; WIDTH]; HALF_FULL_ROUNDS],
}

/// Constrain one Poseidon2 permutation over the columns in `local`.
///
/// After this returns, `local.ending_full_rounds[HALF_FULL_ROUNDS-1].post` is
/// the constrained permutation output — which is what [`crate::wots_air`] chains
/// into the next row's `inputs`.
///
/// Vendored from `p3-poseidon2-air`; see the module docs.
#[allow(clippy::too_many_arguments)]
pub fn eval_permutation<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    constants: &Constants<AB::F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    builder: &mut AB,
    local: &Poseidon2Cols<
        AB::Var,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
) {
    let mut state: [AB::Expr; WIDTH] = local.inputs.clone().map(|x| x.into());

    LinearLayers::external_linear_layer(&mut state);

    for round in 0..HALF_FULL_ROUNDS {
        eval_full_round::<AB, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.beginning_full_rounds[round],
            &constants.beginning_full[round],
            builder,
        );
    }
    for round in 0..PARTIAL_ROUNDS {
        eval_partial_round::<AB, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.partial_rounds[round],
            &constants.partial[round],
            builder,
        );
    }
    for round in 0..HALF_FULL_ROUNDS {
        eval_full_round::<AB, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>(
            &mut state,
            &local.ending_full_rounds[round],
            &constants.ending_full[round],
            builder,
        );
    }
}

#[inline]
fn eval_full_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [AB::Expr; WIDTH],
    full_round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[AB::F; WIDTH],
    builder: &mut AB,
) {
    for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
        *s += r.clone();
        eval_sbox(&full_round.sbox[i], s, builder);
    }
    LinearLayers::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(&full_round.post) {
        builder.assert_eq(state_i.clone(), post_i.clone());
        *state_i = post_i.clone().into();
    }
}

#[inline]
fn eval_partial_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
>(
    state: &mut [AB::Expr; WIDTH],
    partial_round: &PartialRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: &AB::F,
    builder: &mut AB,
) {
    state[0] += round_constant.clone();
    eval_sbox(&partial_round.sbox, &mut state[0], builder);

    builder.assert_eq(state[0].clone(), partial_round.post_sbox.clone());
    state[0] = partial_round.post_sbox.clone().into();

    LinearLayers::internal_linear_layer(state);
}

/// The S-box over a degree-1 expression `x`.
///
/// `REGISTERS` are committed intermediates that keep constraint degree bounded:
/// at degree 7 with one register, the prover commits `x^3` and the circuit checks
/// `committed == x^3` then forms `committed^2 * x`. Without it the constraint
/// would be degree 7 in one step, which inflates the quotient polynomial.
#[inline]
fn eval_sbox<AB, const DEGREE: u64, const REGISTERS: usize>(
    sbox: &SBox<AB::Var, DEGREE, REGISTERS>,
    x: &mut AB::Expr,
    builder: &mut AB,
) where
    AB: AirBuilder,
{
    *x = match (DEGREE, REGISTERS) {
        (3, 0) => x.cube(),
        (5, 0) => x.exp_const_u64::<5>(),
        (7, 0) => x.exp_const_u64::<7>(),
        (5, 1) => {
            let committed_x3: AB::Expr = sbox.0[0].clone().into();
            let x2 = x.square();
            builder.assert_eq(committed_x3.clone(), x2.clone() * x.clone());
            committed_x3 * x2
        }
        (7, 1) => {
            let committed_x3: AB::Expr = sbox.0[0].clone().into();
            builder.assert_eq(committed_x3.clone(), x.cube());
            committed_x3.square() * x.clone()
        }
        (11, 2) => {
            let committed_x3: AB::Expr = sbox.0[0].clone().into();
            let committed_x9: AB::Expr = sbox.0[1].clone().into();
            let x2 = x.square();
            builder.assert_eq(committed_x3.clone(), x2.clone() * x.clone());
            builder.assert_eq(committed_x9.clone(), committed_x3.cube());
            committed_x9 * x2
        }
        _ => panic!("Unexpected (DEGREE, REGISTERS) of ({DEGREE}, {REGISTERS})"),
    }
}
