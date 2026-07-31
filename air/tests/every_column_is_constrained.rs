//! **The per-column argument, owed since the first mutation sweep.**
//!
//! `air/COVERAGE.md` names two gaps this file closes, and they are the same gap
//! seen from two sides.
//!
//! **Gap one: nine of sixteen constraints survive the mutation sweep.** Deleting
//! constraint 4, or 5–10, or 13 leaves every test still passing — not because
//! those constraints are dead, but because each pins a **permutation input lane**,
//! so tampering with the lane also breaks the permutation constraint. Delete the
//! target and something else still objects. A proof-level test cannot separate
//! them: it sees one boolean, "the proof failed", and cannot say which rule did
//! the failing. The excuse on record is that soundness is *inherited* from the
//! deleted `transfer_air.rs`, whose identical constraints swept clean. An
//! inheritance argument is not a test.
//!
//! **Gap two, in COVERAGE.md's own words:** the sweep "does not find a column that
//! no constraint mentions at all: deleting nothing changes nothing. That gap is
//! the per-column argument, and it is still owed." This is the graver of the two.
//! **A hand-written AIR is sound only if every column is constrained** — an
//! unconstrained column is a free variable a prover may choose, and a free
//! variable in the wrong place mints money (`AUDIT-BRIEF.md` §1).
//!
//! ## The technique: evaluate the AIR, do not prove
//!
//! `Probe` is an `AirBuilder` that evaluates constraints **concretely over
//! BabyBear** and records every assertion separately, by index. Constraint
//! evaluation is deterministic, so assertion *k* always comes from the same
//! constraint — which means a perturbation's failure set names which rules
//! objected, where a proof would only say that one did.
//!
//! The permutation's assertions are a measured prefix: `eval` calls
//! `eval_permutation` first, and running that block alone counts exactly how many
//! assertions it emits. **Everything at or above that index is one of our own
//! sixteen constraints.** So the mutual-defence excuse becomes checkable: perturb
//! a lane and require a failure *above* the prefix — an objection that is ours,
//! independent of the permutation.
//!
//! This is exactly the `sponge_lanes_are_tied.rs` technique COVERAGE.md names as
//! the fix, ported to this circuit. That file went with `TransferAir`; the
//! mock-builder pattern survived in `poseidon2_differential.rs` and is reused here.
//!
//! ## What this does not do
//!
//! It cannot tell you a constraint is **right** — only that some rule notices when
//! a cell moves. A constraint that is present, defended, and wrong passes
//! everything here, which is what the external review is for. And it perturbs one
//! cell at a time, so a hole that needs two coordinated changes is out of reach.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::Poseidon2Cols;

use uv_air::authproto_air::{self, AuthProtoAir, HEIGHT, NUM_COLS, NUM_PUBLIC_VALUES};
use uv_air::poseidon2::{Digest, WIDTH};
use uv_air::poseidon2_eval::{
    constants, eval_permutation, HALF_FULL_ROUNDS, P2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE,
    SBOX_REGISTERS,
};
use uv_air::prove::TransferPublics;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

/// Layout facts this file's lane arithmetic rests on, checked **at compile time**.
///
/// `Poseidon2Cols` is `export` then `inputs`, so column 0 is the export flag and
/// the permutation input lanes are columns `1..=WIDTH`. Capacity begins at lane
/// `DIGEST` and constraint 5 covers `DIGEST..WIDTH-2`, with lanes 14 and 15
/// reserved for constraints 6 and 7.
///
/// These were runtime `assert!`s until clippy pointed out — correctly — that both
/// sides are compile-time constants, so the assertion could never fail at run
/// time. As `const` assertions they fail the *build* instead, which is what a
/// layout invariant deserves: if an upstream change moves these, nothing here
/// silently starts probing the wrong column.
const DIGEST: usize = 8;
const _: () = assert!(
    P2_COLS > WIDTH,
    "the permutation block must own more columns than just its inputs"
);
const _: () = assert!(
    1 + DIGEST < 1 + WIDTH - 2,
    "the first capacity lane must fall inside constraint 5's range"
);
const _: () = assert!(
    WIDTH == 16,
    "lanes 14 and 15 are constraints 6 and 7 by number, not by position from the end"
);

/// An `AirBuilder` that evaluates the AIR concretely and remembers which
/// assertions failed, by index.
struct Probe {
    window: RowMajorMatrix<BabyBear>,
    publics: Vec<BabyBear>,
    first: bool,
    last: bool,
    transition: bool,
    /// Indices of assertions whose expression was non-zero.
    failed: Vec<usize>,
    seen: usize,
}

impl AirBuilder for Probe {
    type F = BabyBear;
    type Expr = BabyBear;
    type Var = BabyBear;
    type M = RowMajorMatrix<BabyBear>;

    fn main(&self) -> Self::M {
        self.window.clone()
    }
    fn is_first_row(&self) -> Self::Expr {
        if self.first {
            BabyBear::ONE
        } else {
            BabyBear::ZERO
        }
    }
    fn is_last_row(&self) -> Self::Expr {
        if self.last {
            BabyBear::ONE
        } else {
            BabyBear::ZERO
        }
    }
    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        if self.transition {
            BabyBear::ONE
        } else {
            BabyBear::ZERO
        }
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let v: BabyBear = x.into();
        let idx = self.seen;
        self.seen += 1;
        if v != BabyBear::ZERO {
            self.failed.push(idx);
        }
    }
}

impl AirBuilderWithPublicValues for Probe {
    type PublicVar = BabyBear;
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.publics
    }
}

/// Evaluate the whole AIR over the two-row window starting at `row`.
fn eval_window(
    trace: &RowMajorMatrix<BabyBear>,
    publics: &[BabyBear],
    row: usize,
) -> (Vec<usize>, usize) {
    let h = trace.height();
    // The window the prover would see. On the last row there is no `next`, and
    // `is_transition_window` is zero there, so the values are never used — but
    // `eval` still calls `row_slice(1)`, so it must exist.
    let next = (row + 1) % h;
    let mut values = Vec::with_capacity(2 * NUM_COLS);
    values.extend_from_slice(&trace.values[row * NUM_COLS..(row + 1) * NUM_COLS]);
    values.extend_from_slice(&trace.values[next * NUM_COLS..(next + 1) * NUM_COLS]);

    let mut probe = Probe {
        window: RowMajorMatrix::new(values, NUM_COLS),
        publics: publics.to_vec(),
        first: row == 0,
        last: row + 1 == h,
        transition: row + 1 < h,
        failed: Vec::new(),
        seen: 0,
    };
    AuthProtoAir::default().eval(&mut probe);
    (probe.failed, probe.seen)
}

/// How many assertions the **permutation block alone** emits, measured rather
/// than assumed. Assertions at or above this index belong to our own sixteen
/// constraints, which is what makes "our constraint objected" a checkable claim.
fn permutation_assertion_count(trace: &RowMajorMatrix<BabyBear>) -> usize {
    type Cols<'a> = &'a Poseidon2Cols<
        BabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;
    struct Counter {
        seen: usize,
    }
    impl AirBuilder for Counter {
        type F = BabyBear;
        type Expr = BabyBear;
        type Var = BabyBear;
        type M = RowMajorMatrix<BabyBear>;
        fn main(&self) -> Self::M {
            RowMajorMatrix::new(vec![BabyBear::ZERO; 1], 1)
        }
        fn is_first_row(&self) -> Self::Expr {
            BabyBear::ZERO
        }
        fn is_last_row(&self) -> Self::Expr {
            BabyBear::ZERO
        }
        fn is_transition_window(&self, _s: usize) -> Self::Expr {
            BabyBear::ONE
        }
        fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {
            self.seen += 1;
        }
    }
    let row = &trace.values[..NUM_COLS];
    let p2: Cols = row[..P2_COLS].borrow();
    let mut c = Counter { seen: 0 };
    eval_permutation::<
        Counter,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&constants(), &mut c, p2);
    c.seen
}

fn honest() -> (RowMajorMatrix<BabyBear>, Vec<BabyBear>) {
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

    let w = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };
    (authproto_air::generate(&w), pv)
}

/// The control, and the reason every assertion below means anything: the honest
/// trace satisfies every constraint on every row.
#[test]
fn the_honest_trace_satisfies_every_constraint_on_every_row() {
    let (trace, pv) = honest();
    assert_eq!(trace.height(), HEIGHT);
    assert_eq!(trace.width(), NUM_COLS);

    let mut total = 0usize;
    for row in 0..HEIGHT {
        let (failed, seen) = eval_window(&trace, &pv, row);
        assert!(
            failed.is_empty(),
            "the honest trace violates constraints at row {row}: assertion indices {failed:?}"
        );
        total += seen;
        assert!(seen > 0, "row {row} evaluated no constraints at all");
    }
    // Reported, not just asserted: these are the numbers COVERAGE.md quotes.
    println!(
        "honest control: {total} assertions over {HEIGHT} rows x {NUM_COLS} columns, \
         all satisfied"
    );
    // A per-row count that would notice an `eval` that stopped early.
    assert!(
        total > 1000,
        "only {total} assertions over the whole trace — suspiciously few for a \
         16-row circuit with a Poseidon2 permutation on every row"
    );
}

/// **Every column is mentioned by at least one constraint.**
///
/// For each of the 361 columns, perturb it on every row in turn and require that
/// *some* constraint objects somewhere. A column no constraint ever mentions is a
/// free variable in a consensus circuit: a prover may put anything there, and the
/// proof still verifies.
#[test]
fn no_column_is_a_free_variable() {
    let (trace, pv) = honest();
    let mut unconstrained: Vec<usize> = Vec::new();

    for col in 0..NUM_COLS {
        let mut noticed = false;
        'rows: for row in 0..HEIGHT {
            for delta in [BabyBear::ONE, BabyBear::from_u32(0x1234_5678)] {
                let mut t = trace.clone();
                t.values[row * NUM_COLS + col] += delta;
                // A perturbation at `row` is visible to the window starting there
                // and to the one before it, since constraints read `local`/`next`.
                for w in [row.saturating_sub(1), row] {
                    let (failed, _) = eval_window(&t, &pv, w);
                    if !failed.is_empty() {
                        noticed = true;
                        break 'rows;
                    }
                }
            }
        }
        if !noticed {
            unconstrained.push(col);
        }
    }

    println!(
        "per-column probe: all {NUM_COLS} columns provoke at least one constraint \
         failure when perturbed"
    );
    assert!(
        unconstrained.is_empty(),
        "{} of {NUM_COLS} columns are mentioned by NO constraint at any row — each \
         is a field element a prover may choose freely inside the circuit that \
         authorizes payments: {:?}",
        unconstrained.len(),
        unconstrained
    );
}

/// **The nine mutation survivors, given direct evidence at last.**
///
/// Each perturbation below targets a permutation input lane — the cluster whose
/// members "defend each other" so a deleted constraint goes unnoticed. The
/// assertion is not merely that *something* objected: it is that something
/// objected **at or above the permutation's assertion prefix**, i.e. one of our
/// own sixteen constraints, not the permutation covering for it.
#[test]
fn our_own_constraints_object_to_a_tampered_lane_not_only_the_permutation() {
    let (trace, pv) = honest();
    let n_perm = permutation_assertion_count(&trace);
    assert!(
        n_perm > 0 && n_perm < 4000,
        "the measured permutation prefix ({n_perm}) is implausible; the mapping \
         from assertion index to constraint is the basis of this whole test"
    );

    // `export` is column 0, the permutation input lanes are columns 1..=WIDTH
    // (`Poseidon2Cols` is `export` then `inputs`), and our own registers start at
    // `SP = P2_COLS`. Asserted rather than assumed, because the whole test rests
    // on it and an upstream layout change must break loudly.

    // **Lane arithmetic, spelled out, because getting it wrong makes this test
    // pass for the wrong reason.** The first pass of this file aimed the "5/9"
    // case at column `1 + WIDTH - 2` = lane 14 — which is *constraint 6's* lane,
    // the input length. The case passed (6 objected), the label claimed 5 and 9,
    // and the mutation sweep gave the game away by leaving exactly those two
    // alive. A test whose label and target disagree is worse than a missing test.
    //
    // Constraint 5 zeroes the capacity lanes `DIGEST..WIDTH-2` on a **start** row.
    // Constraint 9 carries the capacity lanes `DIGEST..WIDTH` onto a **continuing**
    // row. Rate lanes are `0..DIGEST`, and lanes 14/15 belong to 6 and 7.
    let cap_lane = 1 + DIGEST; // column of the first capacity lane
    let rate_lane = 1; // column of the first rate lane

    let cases: [(&str, usize, usize); 9] = [
        // (what it should provoke, column, row)
        (
            "4: a padding row feeds the permutation nothing",
            rate_lane,
            HEIGHT - 1,
        ),
        ("5: a sponge start has zeroed capacity", cap_lane, 0),
        ("6: input length in lane 14", 1 + 14, 0),
        ("7: domain tag in lane 15", 1 + 15, 0),
        ("8: a start row's rate is its first chunk", rate_lane, 0),
        ("9: capacity carries onto a continuing row", cap_lane, 1),
        ("10: rate carry and absorb injection", rate_lane, 1),
        (
            "13: bus constancy (nullifier key)",
            uv_air::authproto_air::NK,
            3,
        ),
        (
            "13: bus constancy (spend anchor)",
            uv_air::authproto_air::T,
            3,
        ),
    ];

    println!("permutation assertion prefix: {n_perm} (indices >= this are our own rules)");
    let mut unattributed = Vec::new();
    for (what, col, row) in cases {
        let mut ours = false;
        for delta in [BabyBear::ONE, BabyBear::from_u32(0x0BAD_F00D)] {
            let mut t = trace.clone();
            t.values[row * NUM_COLS + col] += delta;
            for w in [row.saturating_sub(1), row] {
                let (failed, _) = eval_window(&t, &pv, w);
                if failed.iter().any(|&i| i >= n_perm) {
                    ours = true;
                }
            }
        }
        if !ours {
            unattributed.push(what);
        }
    }

    assert!(
        unattributed.is_empty(),
        "for these lanes, ONLY the permutation constraint objected — our own rule \
         did not fire, so the mutation sweep's mutual-defence explanation is the \
         whole story and the constraint has no independent evidence: {unattributed:?}"
    );
}

// ---------------------------------------------------------------------------
// Pairwise: the two-cell holes neither the sweep nor the probe above can see.
// ---------------------------------------------------------------------------

/// **Both existing circuit checks perturb exactly one thing.** The mutation
/// sweep deletes one constraint; the probe above moves one cell. 16/16 and
/// 361/361 are real results and they are both *single*-perturbation results.
///
/// An attacker does not perturb randomly. They solve for a satisfying witness —
/// and the cheapest satisfying witness that is not the honest one is usually a
/// pair of cells that move together so their effects cancel. That is invisible
/// to everything else in this repository.
///
/// **What this actually covers, stated precisely, because the number is going to
/// be quoted.** For every ordered pair of distinct columns in a row, it perturbs
/// both at once with deltas chosen to cancel under a *linear* relation
/// (`+d, -d` and `+d, -2d`, over two magnitudes), and requires that some
/// constraint still objects. It finds **linearly compensating pairs**. It does
/// not find pairs that cancel only through the S-box's degree-7 nonlinearity,
/// and it does not touch triples.
///
/// Linear is the right place to look first: the sponge-lane constraints — the
/// cluster that "defends itself", the one the mutation sweep could not separate,
/// and the one an inheritance argument used to cover — are all linear in the
/// cells they read. If a compensating pair exists anywhere, it is most likely
/// there.
///
/// **Not run in CI**: minutes, not seconds. It is a pre-release and
/// post-circuit-change run, and `air/COVERAGE.md` records the number it last
/// produced. Run it with:
///
/// ```text
/// cargo test -p uv-air --release --test every_column_is_constrained -- --ignored --nocapture
/// ```
#[test]
#[ignore = "minutes: pre-release / post-circuit-change, not CI"]
fn no_pair_of_columns_can_cancel_each_other() {
    let (trace, pv) = honest();
    let d1 = BabyBear::ONE;
    let d2 = BabyBear::from_u32(0x1234_5678);

    // Deltas applied to (a, b) together. Each pair is a linear cancellation
    // shape: if some constraint reads `a + b`, `a - b`, or `a + 2b`, one of
    // these makes the pair invisible to it unless another rule objects.
    let shapes: [(BabyBear, BabyBear); 6] = [
        (d1, -d1),
        (-d1, d1),
        (d1, d1),
        (d2, -d2),
        (d1, -d1 - d1),
        (d1 + d1, -d1),
    ];

    // A pair only counts as **compensating** if each cell is caught ALONE at this
    // same row and the two together are not. Without that precondition the test
    // reports cells that are simply unconstrained at that row, which is a
    // different (and separately tracked) finding — and it is what the first
    // version of this test did, reporting 378 "compensating pairs" that were
    // nothing of the kind. The assertion message claimed "while each is caught
    // alone" and nothing checked it.
    let caught_alone = |row: usize, col: usize| -> bool {
        for delta in [d1, d2] {
            let mut t = trace.clone();
            t.values[row * NUM_COLS + col] += delta;
            for w in [row.saturating_sub(1), row] {
                let (failed, _) = eval_window(&t, &pv, w);
                if !failed.is_empty() {
                    return true;
                }
            }
        }
        false
    };

    let mut compensating: Vec<(usize, usize, usize)> = Vec::new();
    let mut checked: u64 = 0;
    let mut pairs_considered: u64 = 0;

    for row in 0..HEIGHT {
        // Only columns that are individually pinned at this row can form a
        // compensating pair here.
        let pinned: Vec<usize> = (0..NUM_COLS).filter(|&c| caught_alone(row, c)).collect();
        for (i, &a) in pinned.iter().enumerate() {
            for &b in &pinned[i + 1..] {
                pairs_considered += 1;
                let mut noticed = false;
                'shapes: for (da, db) in shapes {
                    let mut t = trace.clone();
                    t.values[row * NUM_COLS + a] += da;
                    t.values[row * NUM_COLS + b] += db;
                    checked += 1;
                    for w in [row.saturating_sub(1), row] {
                        let (failed, _) = eval_window(&t, &pv, w);
                        if !failed.is_empty() {
                            noticed = true;
                            break 'shapes;
                        }
                    }
                }
                if !noticed {
                    compensating.push((row, a, b));
                }
            }
        }
    }

    println!(
        "pairwise probe: {pairs_considered} pairs of individually-pinned columns, \
         {checked} two-cell perturbations"
    );
    println!("compensating pairs found: {}", compensating.len());

    assert!(
        compensating.is_empty(),
        "{} pairs of columns are each caught alone at their row, yet can be moved \
         TOGETHER with no constraint objecting. Each is a two-variable degree of \
         freedom inside the circuit that authorizes payments, and it is exactly the \
         shape a prover solving for a satisfying witness would find. First few \
         (row, col_a, col_b): {:?}",
        compensating.len(),
        &compensating[..compensating.len().min(12)]
    );
}

/// **Which cells are free, per row.** A measurement, printed.
#[test]
#[ignore = "diagnostic"]
fn map_the_unconstrained_cells() {
    let (trace, pv) = honest();
    let d1 = BabyBear::ONE;
    let d2 = BabyBear::from_u32(0x1234_5678);
    let mut total = 0usize;
    for row in 0..HEIGHT {
        let mut free: Vec<usize> = Vec::new();
        for col in 0..NUM_COLS {
            let mut caught = false;
            for delta in [d1, d2] {
                let mut t = trace.clone();
                t.values[row * NUM_COLS + col] += delta;
                for w in [row.saturating_sub(1), row] {
                    let (failed, _) = eval_window(&t, &pv, w);
                    if !failed.is_empty() {
                        caught = true;
                    }
                }
            }
            if !caught {
                free.push(col);
            }
        }
        total += free.len();
        if !free.is_empty() {
            let lo = *free.iter().min().unwrap();
            let hi = *free.iter().max().unwrap();
            println!(
                "row {row:2}: {:3} free cells, columns {lo}..={hi}",
                free.len()
            );
        }
    }
    println!(
        "TOTAL free cells in the honest trace: {total} of {}",
        HEIGHT * NUM_COLS
    );
}

#[test]
#[ignore = "diagnostic"]
fn diagnose_the_pairwise_finding() {
    let (trace, pv) = honest();
    let n_perm = permutation_assertion_count(&trace);
    println!("permutation assertion prefix = {n_perm}");
    let d = BabyBear::ONE;

    for &(row, a, b) in &[
        (15usize, 314usize, 315usize),
        (15, 314, 322),
        (14, 314, 315),
    ] {
        println!("\n=== row {row}, cols {a} and {b} ===");
        // each alone, at THIS row
        for (label, pa, pb) in [
            ("a alone", Some(d), None),
            ("b alone", None, Some(d)),
            ("a+, b-", Some(d), Some(-d)),
        ] {
            let mut t = trace.clone();
            if let Some(x) = pa {
                t.values[row * NUM_COLS + a] += x;
            }
            if let Some(x) = pb {
                t.values[row * NUM_COLS + b] += x;
            }
            let mut all: Vec<usize> = Vec::new();
            for w in [row.saturating_sub(1), row] {
                let (failed, _) = eval_window(&t, &pv, w);
                for f in failed {
                    if !all.contains(&f) {
                        all.push(f);
                    }
                }
            }
            all.sort_unstable();
            let ours: Vec<_> = all.iter().filter(|&&i| i >= n_perm).collect();
            println!(
                "  {label:8} -> {} assertions fired, {} of them ours {:?}",
                all.len(),
                ours.len(),
                &all[..all.len().min(8)]
            );
        }
    }
}
