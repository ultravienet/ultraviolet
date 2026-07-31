//! Differential test of the *in-circuit* Poseidon2 permutation (the vendored
//! `poseidon2_eval::eval_permutation`, evaluated over a concrete honest
//! witness) against the *host* `Poseidon2BabyBear` permutation, over the FULL
//! 16-element state, on random inputs.
//!
//! Method: a mock `AirBuilder` whose `F = Expr = Var = BabyBear`. Evaluating
//! the vendored constraints with it turns every `assert_eq` into a concrete
//! field equality check, so:
//!   1. every vendored constraint must hold on the honest witness, and
//!   2. the column the AIR treats as "the permutation output"
//!      (`ending_full_rounds[HALF_FULL_ROUNDS-1].post`) must equal
//!      `Poseidon2BabyBear::permute(input)` on all 16 lanes.
//!
//! **Why this exists.** `poseidon2_eval.rs` is vendored from upstream, so we own
//! its bugs, and a permutation that disagrees with the host's forges every
//! commitment in the system. The tests that were here before this one compared
//! circuit and host only on lanes 0..8, through a single fixed witness. This
//! covers the whole state on random inputs. An adversarial reviewer wrote it
//! after finding that no such test existed.
//!
//! It is an *honest-witness* test and cannot show soundness: it proves the
//! circuit agrees with the host on the cases tried, never that no other witness
//! satisfies the constraints.

use core::borrow::Borrow;

use p3_air::AirBuilder;
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows, num_cols, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use uv_air::poseidon2::{self, WIDTH};
use uv_air::poseidon2_eval::{
    constants, eval_permutation, HALF_FULL_ROUNDS, P2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE,
    SBOX_REGISTERS,
};

type Cols<'a> = &'a Poseidon2Cols<
    BabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// An `AirBuilder` that evaluates constraints concretely over `BabyBear`.
struct Checker {
    failures: Vec<BabyBear>,
    seen: usize,
}

impl AirBuilder for Checker {
    type F = BabyBear;
    type Expr = BabyBear;
    type Var = BabyBear;
    type M = RowMajorMatrix<BabyBear>;

    fn main(&self) -> Self::M {
        // `eval_permutation` never calls `main()`; it is handed `local` directly.
        RowMajorMatrix::new(vec![BabyBear::ZERO; 1], 1)
    }
    fn is_first_row(&self) -> Self::Expr {
        BabyBear::ZERO
    }
    fn is_last_row(&self) -> Self::Expr {
        BabyBear::ZERO
    }
    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        BabyBear::ONE
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let v: BabyBear = x.into();
        self.seen += 1;
        if v != BabyBear::ZERO {
            self.failures.push(v);
        }
    }
}

fn upstream_constants() -> RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    use p3_baby_bear::{
        BABYBEAR_RC16_EXTERNAL_FINAL, BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
    };
    RoundConstants::new(
        BABYBEAR_RC16_EXTERNAL_INITIAL,
        BABYBEAR_RC16_INTERNAL,
        BABYBEAR_RC16_EXTERNAL_FINAL,
    )
}

/// Build honest Poseidon2 witness rows exactly the way `uv_air::trace` does.
fn witness(states: Vec<[BabyBear; WIDTH]>) -> RowMajorMatrix<BabyBear> {
    generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(states, &upstream_constants(), 0)
}

fn run_eval(row: &[BabyBear]) -> (Checker, [BabyBear; WIDTH]) {
    let p2: Cols = row[..P2_COLS].borrow();
    let mut ck = Checker {
        failures: Vec::new(),
        seen: 0,
    };
    eval_permutation::<
        Checker,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&constants(), &mut ck, p2);
    let post = p2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
    (ck, post)
}

/// THE differential test: in-circuit permutation == host permutation, all 16
/// lanes, random full-width inputs.
#[test]
fn in_circuit_permutation_matches_host_on_random_full_states() {
    let perm = poseidon2::permutation();
    let mut rng = SmallRng::seed_from_u64(0xC0FFEE);

    let mut states: Vec<[BabyBear; WIDTH]> = (0..64)
        .map(|_| core::array::from_fn(|_| BabyBear::from_u32(rng.random::<u32>() % 0x7800_0001)))
        .collect();
    states.push([BabyBear::ZERO; WIDTH]);
    states.push([BabyBear::ONE; WIDTH]);
    states.push(core::array::from_fn(|i| BabyBear::from_u32(i as u32)));
    states.push([BabyBear::NEG_ONE; WIDTH]); // p-1 everywhere: the field's edge
    while !states.len().is_power_of_two() {
        states.push([BabyBear::ZERO; WIDTH]);
    }

    let trace = witness(states.clone());
    assert_eq!(trace.width, P2_COLS, "vendored layout must match upstream");

    for (r, input) in states.iter().enumerate() {
        let row = &trace.values[r * P2_COLS..(r + 1) * P2_COLS];
        let (ck, circuit_out) = run_eval(row);

        assert!(ck.seen > 0, "no constraints were evaluated — vacuous test");
        assert!(
            ck.failures.is_empty(),
            "row {r}: {} of {} vendored constraints FAILED on an honest witness",
            ck.failures.len(),
            ck.seen
        );

        let mut host_out = *input;
        perm.permute_mut(&mut host_out);

        assert_eq!(
            circuit_out, host_out,
            "row {r}: in-circuit permutation output differs from host \
             Poseidon2BabyBear over the full 16-lane state\ninput = {input:?}"
        );
    }
}

/// Negative control: the checker must detect a corrupted witness, and every
/// Poseidon2 column except `export` must be constrained by the vendored eval.
#[test]
fn every_poseidon2_column_except_export_is_constrained_by_the_vendored_eval() {
    let mut rng = SmallRng::seed_from_u64(7);
    let states: Vec<[BabyBear; WIDTH]> = (0..2)
        .map(|_| core::array::from_fn(|_| BabyBear::from_u32(rng.random::<u32>() % 0x7800_0001)))
        .collect();
    let trace = witness(states);

    let mut unnoticed = Vec::new();
    for c in 0..P2_COLS {
        let mut row = trace.values[0..P2_COLS].to_vec();
        row[c] += BabyBear::ONE;
        let (ck, _) = run_eval(&row);
        if ck.failures.is_empty() {
            unnoticed.push(c);
        }
    }
    assert_eq!(
        unnoticed,
        vec![0],
        "columns unconstrained by the vendored permutation eval \
         (0 = `export`, which upstream also leaves free)"
    );
}

/// The partial-round count in the circuit is the count the host uses.
#[test]
fn partial_round_count_is_thirteen_everywhere() {
    use p3_baby_bear::BABYBEAR_RC16_INTERNAL;
    assert_eq!(PARTIAL_ROUNDS, 13);
    assert_eq!(HALF_FULL_ROUNDS, 4);
    assert_eq!(BABYBEAR_RC16_INTERNAL.len(), 13);
    assert_eq!(constants().partial.len(), 13);
    assert_eq!(constants().partial, BABYBEAR_RC16_INTERNAL);
    // The other two tables too — the repo's own unit test checks only `partial`.
    assert_eq!(
        constants().beginning_full,
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL
    );
    assert_eq!(
        constants().ending_full,
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL
    );
    assert_eq!(
        P2_COLS,
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    );

    // Behavioural: a 20-partial-round permutation must NOT reproduce the host
    // output, i.e. the round count is observable and 13 is the observed one.
    let perm = poseidon2::permutation();
    let mut st = [BabyBear::ONE; WIDTH];
    perm.permute_mut(&mut st);

    const ALT_PARTIAL: usize = 20;
    let alt_constants = RoundConstants::<BabyBear, WIDTH, HALF_FULL_ROUNDS, ALT_PARTIAL>::new(
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL,
        core::array::from_fn(|i| *BABYBEAR_RC16_INTERNAL.get(i).unwrap_or(&BabyBear::ZERO)),
        p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL,
    );
    let alt = generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        ALT_PARTIAL,
    >(vec![[BabyBear::ONE; WIDTH]; 1], &alt_constants, 0);
    let w = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, ALT_PARTIAL>();
    let alt_cols: &Poseidon2Cols<
        BabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        ALT_PARTIAL,
    > = alt.values[..w].borrow();
    assert_ne!(
        alt_cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post,
        st,
        "a 20-partial-round permutation must not equal the host's output"
    );
}

/// Witness generator (generic linear layers) vs host (optimised Monty layers),
/// all 16 lanes.
#[test]
fn generic_and_optimised_linear_layers_agree() {
    let perm = poseidon2::permutation();
    let mut rng = SmallRng::seed_from_u64(0xBEEF);
    let states: Vec<[BabyBear; WIDTH]> = (0..32)
        .map(|_| core::array::from_fn(|_| BabyBear::from_u32(rng.random::<u32>() % 0x7800_0001)))
        .collect();
    let trace = witness(states.clone());
    for (r, input) in states.iter().enumerate() {
        let row = &trace.values[r * P2_COLS..(r + 1) * P2_COLS];
        let p2: Cols = row[..P2_COLS].borrow();
        let mut host = *input;
        perm.permute_mut(&mut host);
        assert_eq!(
            p2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post,
            host,
            "witness generator diverges from host at row {r}"
        );
    }
}

// ---------------------------------------------------------------------------
// Independent structural checks of the linear layers the circuit uses,
// reconstructed column-by-column from unit vectors and compared against the
// Poseidon2 paper's definitions (NOT against p3's own code).
// ---------------------------------------------------------------------------

fn matrix_of(f: impl Fn(&mut [BabyBear; WIDTH])) -> [[BabyBear; WIDTH]; WIDTH] {
    let mut m = [[BabyBear::ZERO; WIDTH]; WIDTH];
    for j in 0..WIDTH {
        let mut e = [BabyBear::ZERO; WIDTH];
        e[j] = BabyBear::ONE;
        f(&mut e);
        for (i, row) in m.iter_mut().enumerate() {
            row[j] = e[i];
        }
    }
    m
}

/// The external layer must be the Poseidon2 paper's M_E for t = 16: a 4x4 block
/// matrix, `2*M4` on the diagonal blocks and `M4` off them, where
/// M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
#[test]
fn external_linear_layer_is_the_paper_mds() {
    let got = matrix_of(GenericPoseidon2LinearLayersBabyBear::external_linear_layer);
    const M4: [[u32; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    let mut want = [[BabyBear::ZERO; WIDTH]; WIDTH];
    for bi in 0..4 {
        for bj in 0..4 {
            let scale = if bi == bj { 2u32 } else { 1 };
            for i in 0..4 {
                for j in 0..4 {
                    want[bi * 4 + i][bj * 4 + j] = BabyBear::from_u32(scale * M4[i][j]);
                }
            }
        }
    }
    assert_eq!(
        got, want,
        "external layer is not the Poseidon2 M_E for t=16"
    );
}

/// The internal layer must be `J + Diag(V)` with the diagonal p3 documents for
/// BabyBear16:
/// [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]
#[test]
fn internal_linear_layer_is_ones_plus_the_documented_diagonal() {
    use p3_field::Field;
    let got = matrix_of(GenericPoseidon2LinearLayersBabyBear::internal_linear_layer);

    let inv2 = |k: u32| BabyBear::from_u32(2).exp_u64(k as u64).inverse();
    let two = BabyBear::from_u32(2);
    let diag: [BabyBear; WIDTH] = [
        -two,
        BabyBear::ONE,
        two,
        inv2(1),
        BabyBear::from_u32(3),
        BabyBear::from_u32(4),
        -inv2(1),
        -BabyBear::from_u32(3),
        -BabyBear::from_u32(4),
        inv2(8),
        inv2(2),
        inv2(3),
        inv2(27),
        -inv2(8),
        -inv2(4),
        -inv2(27),
    ];

    let mut want = [[BabyBear::ONE; WIDTH]; WIDTH];
    for (i, row) in want.iter_mut().enumerate() {
        row[i] += diag[i];
    }
    assert_eq!(
        got, want,
        "internal layer is not J + Diag(V) with the documented V"
    );
    for (i, d) in diag.iter().enumerate() {
        assert_ne!(*d, BabyBear::ZERO, "diagonal entry {i} is zero");
    }
}

/// The S-box really is x^7 and x^7 is a bijection on BabyBear.
#[test]
fn sbox_is_degree_seven() {
    use p3_field::PrimeField32;
    assert_eq!(SBOX_DEGREE, 7);
    assert_eq!(SBOX_REGISTERS, 1);
    let mut rng = SmallRng::seed_from_u64(3);
    for _ in 0..64 {
        let x = BabyBear::from_u32(rng.random::<u32>() % 0x7800_0001);
        let x3 = x * x * x;
        // The (7,1) arm forms committed_x3^2 * x with committed_x3 == x^3.
        assert_eq!(x3 * x3 * x, x.exp_u64(7));
    }
    let pm1 = (BabyBear::ORDER_U32 - 1) as u64;
    let gcd = |mut a: u64, mut b: u64| {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    };
    assert_eq!(gcd(7, pm1), 1, "x^7 is not a bijection on BabyBear");
}
