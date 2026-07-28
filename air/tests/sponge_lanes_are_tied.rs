//! Which lanes of the sponge section does the tie table actually read?
//!
//! Rows 1005..=1022 of the transfer trace are eighteen sponge rows, one
//! Poseidon2 permutation each. A row's permutation input is sixteen field
//! elements — "lanes" — and the lanes ARE the sponge state: there are no
//! separate witness columns for the private values a note commits to. Some
//! lanes are pinned by constraints 20-25 (the tie table): to a public value, to
//! a bus column, or to the previous row's permutation output. The rest are
//! legitimately free, because they hold private witness the prover is supposed
//! to choose — note randomness, the output notes' owner keys and anchors.
//!
//! A lane that *should* be pinned but is not is a missing tie-table entry, and
//! a missing entry is a soundness hole: the prover puts something else there.
//! This test measures the free set and compares it, position by position,
//! against the set the audit hand-traced.
//!
//! ## Method
//!
//! One honest transfer, its real trace, and a mock `AirBuilder` whose
//! `F = Expr = Var = BabyBear`, so every `assert_zero` is a concrete field
//! check (the same trick as `poseidon2_differential.rs`, extended to the whole
//! `TransferAir` — two-row window, selectors, public values). For each sponge
//! row and each of its sixteen lanes: add one to that lane, re-evaluate, and
//! see whether a transfer constraint objects.
//!
//! **Why the row's Poseidon2 block is deliberately NOT regenerated.** The
//! obvious probe is to perturb a lane and then rebuild the row's permutation
//! witness so the permutation itself still holds. That probe does not work
//! here, and it fails in the direction that hides holes. Rebuilding changes the
//! row's permutation *output*, and every sponge row's output is read by
//! something: constraint 24 carries it into the next row's capacity, or
//! constraints 26/32 pin it to a public digest. So every lane comes back
//! PINNED, including lanes nothing ties, and the probe reports a clean circuit
//! no matter what the tie table says. That is not a worry, it was measured:
//! the rebuilt-block version of this sweep finds **0 free lanes of 288** — it
//! cannot detect a missing tie at all.
//!
//! So the perturbation is left raw and the failures are separated by *which*
//! constraint raised them. The permutation's own constraints do object, which
//! is exactly what makes the perturbation real (control 1 below requires it on
//! every single lane), and they are excluded. Only the transfer-specific
//! constraints count as a tie. The boundary is measured rather than written
//! down: `WotsAir` is the chain section on its own, so the number of assertions
//! it raises is the number `TransferAir` raises before its first sponge
//! constraint.
//!
//! Two windows are evaluated per lane, because the constraints read a sponge
//! row's inputs from both sides of a transition:
//!
//! - window `(r-1, r)` — the row under test is `next`; constraints 24 (capacity
//!   carry) and 25 (rate carry + absorb) read it. Nothing else in the window
//!   touches the perturbed row, so nothing else can fire.
//! - window `(r, r+1)` — the row under test is `local`; constraints 20-23 (the
//!   start-row capacity, length, domain tag and first chunk) read it.
//!
//! ## What this proves, and what it does not
//!
//! It is an honest-witness *structural* probe. It shows which lanes some
//! transfer constraint reads — no more. It does not show that the constraints
//! that do read a lane pin it to the right thing, and it does not show the
//! constraint set is collectively sufficient: a lane can be read by a
//! constraint that is satisfiable by many values. It also says nothing about
//! the padding row, the chain section, or any witness other than this one.
//!
//! A free lane is not a bug on its own either. Free is correct for private
//! witness. The finding would be a lane that is free and *shouldn't* be — which
//! is why the expectation below is written out lane by lane with what each one
//! holds, rather than as a count.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::Poseidon2Cols;

use uv_air::prove::TransferPublics;
use uv_air::sponge::{self, Domain};
use uv_air::trace::tips_from_trace;
use uv_air::transfer_air::{TransferAir, AMOUNT_LIMBS, NUM_COLS as T_COLS, SPONGE_ROWS};
use uv_air::transfer_trace::{generate, NoteOpening, TransferWitness};
use uv_air::wots::{self, Digest, N, WIDTH};
use uv_air::wots_air::{
    WotsAir, CHAIN_ROWS, HALF_FULL_ROUNDS, P2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
};

type Cols<'a> = &'a Poseidon2Cols<
    BabyBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// How many assertions the sponge section raises, by constraint. Not needed to
/// classify anything — the chain/sponge boundary is measured — but it is what
/// makes "the numbers below still describe this AIR" checkable, and it is the
/// only thing here that would go stale silently if a constraint were added.
const SPONGE_ASSERTS: usize = 18  // 18: SP empty on the first row
    + 18                          // 19: SP shifts by one
    + 6                           // 20: zeroed capacity on a start row
    + 1                           // 21: input length in lane 14
    + 1                           // 22: domain tag in lane 15
    + 8                           // 23: a start row's first chunk
    + 8                           // 24: capacity carry
    + 8                           // 25: rate carry + absorb (the tie table)
    + 8                           // 26: each sponge's digest is its public value
    + 8                           // 32: the spend anchor
    + 28                          // 27: bus constancy
    + 4                           // 28: conservation
    + 3                           // 29: carries are boolean
    + 16                          // 30: range bits are boolean
    + 1; // 31: limb range routing

/// The lanes that are supposed to be free, and what private value each holds.
///
/// Entries are `(sponge row, first lane, one past the last lane, contents)`.
/// The note-commitment preimage is `asset ‖ amount ‖ owner_pk ‖ anchor ‖ rnd`
/// (36 elements, five rows of rate-8 absorb); the output notes' keys and
/// anchors are free because the payer chooses them, and no constraint in this
/// circuit has anything to compare them against.
const EXPECTED_FREE: [(usize, usize, usize, &str); 10] = [
    (3, 4, 8, "C_in: input note randomness[0..4]"),
    (4, 0, 4, "C_in: input note randomness[4..8]"),
    (8, 4, 8, "C_out0: output 0 owner_pk[0..4]"),
    (9, 0, 8, "C_out0: output 0 owner_pk[4..8] ‖ anchor[0..4]"),
    (10, 0, 8, "C_out0: output 0 anchor[4..8] ‖ randomness[0..4]"),
    (11, 0, 4, "C_out0: output 0 randomness[4..8]"),
    (13, 4, 8, "C_out1: output 1 owner_pk[0..4]"),
    (14, 0, 8, "C_out1: output 1 owner_pk[4..8] ‖ anchor[0..4]"),
    (15, 0, 8, "C_out1: output 1 anchor[4..8] ‖ randomness[0..4]"),
    (16, 0, 4, "C_out1: output 1 randomness[4..8]"),
];

/// The count the audit hand-traced before it could run this probe.
const HAND_TRACED_FREE: usize = 56;

/// The sponge rows that start a sponge — a copy of `transfer_air`'s private
/// `STARTS`, and the module docs' row map. A start row's lanes can only be
/// pinned by constraints 20-23, which read the row as `local`; every other
/// row's lanes can only be pinned by 24-25, which read it as `next`. Control 3
/// checks the measurement really does split that way, which is also what shows
/// neither of the two windows is dead weight.
const START_ROWS: [usize; 5] = [0, 5, 7, 12, 17];

// ---------------------------------------------------------------------------
// The mock builder
// ---------------------------------------------------------------------------

/// An `AirBuilder` that evaluates a two-row window concretely over `BabyBear`
/// and records the *index* of every assertion that failed. The index is what
/// lets a permutation failure be told apart from a tie-table failure.
struct Checker {
    window: RowMajorMatrix<BabyBear>,
    pv: Vec<BabyBear>,
    is_first: BabyBear,
    seen: usize,
    fired: Vec<usize>,
}

impl AirBuilder for Checker {
    type F = BabyBear;
    type Expr = BabyBear;
    type Var = BabyBear;
    type M = RowMajorMatrix<BabyBear>;

    fn main(&self) -> Self::M {
        self.window.clone()
    }
    fn is_first_row(&self) -> Self::Expr {
        self.is_first
    }
    fn is_last_row(&self) -> Self::Expr {
        // Every window here is `(r, r+1)` with `r + 1` inside the trace, so the
        // local row is never the last one.
        BabyBear::ZERO
    }
    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        BabyBear::ONE
    }
    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        if x.into() != BabyBear::ZERO {
            self.fired.push(self.seen);
        }
        self.seen += 1;
    }
}

impl AirBuilderWithPublicValues for Checker {
    type PublicVar = BabyBear;
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.pv
    }
}

fn evaluate<A: Air<Checker>>(air: &A, rows: &[BabyBear], pv: &[BabyBear], first: bool) -> Checker {
    let mut ck = Checker {
        window: RowMajorMatrix::new(rows.to_vec(), T_COLS),
        pv: pv.to_vec(),
        is_first: BabyBear::from_bool(first),
        seen: 0,
        fired: Vec::new(),
    };
    air.eval(&mut ck);
    ck
}

/// Rows `r` and `r + 1`, copied out so a probe can scribble on them.
fn window(trace: &RowMajorMatrix<BabyBear>, r: usize) -> Vec<BabyBear> {
    trace.values[r * T_COLS..(r + 2) * T_COLS].to_vec()
}

/// Column index of permutation input lane `i` within a row.
///
/// `Poseidon2Cols` is `#[repr(C)]` and opens with the `export` flag, so the
/// sixteen lanes are columns 1..17 — but that is derived from the borrowed view
/// rather than written down, so a layout change breaks the test instead of
/// quietly moving the probe onto the wrong columns.
fn lane_col(row: &[BabyBear], i: usize) -> usize {
    let p2: Cols = row[..P2_COLS].borrow();
    let offset =
        (p2.inputs.as_ptr() as usize - row.as_ptr() as usize) / core::mem::size_of::<BabyBear>();
    offset + i
}

// ---------------------------------------------------------------------------
// One honest hop, built the way `bin/measure.rs` builds it
// ---------------------------------------------------------------------------

fn honest_hop() -> (TransferWitness, TransferPublics) {
    let perm = wots::permutation();
    let limbs = |v: u64| -> [BabyBear; AMOUNT_LIMBS] {
        core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
    };
    let open = |tag: u32, v: u64| -> NoteOpening {
        let nullifier_key = [BabyBear::from_u32(tag * 3 + 1); N];
        NoteOpening {
            amount_limbs: limbs(v),
            owner_pk: wots::public_key(&perm, &[tag as u8; 32]),
            anchor: sponge::hash(Domain::SpendAnchor, &nullifier_key),
            nullifier_key,
            randomness: [BabyBear::from_u32(tag * 5 + 2); N],
        }
    };
    let commitment = |o: &NoteOpening, asset: &Digest| -> Digest {
        let mut p = Vec::new();
        p.extend_from_slice(asset);
        p.extend_from_slice(&o.amount_limbs);
        p.extend_from_slice(&o.owner_pk);
        p.extend_from_slice(&o.anchor);
        p.extend_from_slice(&o.randomness);
        sponge::hash(Domain::Note, &p)
    };

    let asset = [BabyBear::from_u32(0xA5); N];
    let input = open(41, 100);
    let outputs = [open(42, 60), open(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);

    let publics = TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outputs[0], &asset),
        commitment(&outputs[1], &asset),
        [BabyBear::ZERO; N], // kernel2::history::GENESIS
        asset,
    );
    // The statement derives its own message; the witness must sign that one,
    // under the INPUT note's seed (constraint 25 ties compress(tips) into the
    // commitment opening).
    let msg = *publics.msg();
    let witness = TransferWitness {
        asset,
        input,
        outputs,
        msg,
        sig: wots::sign(&perm, &[41u8; 32], &msg),
    };
    (witness, publics)
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

#[test]
fn the_free_sponge_lanes_are_exactly_the_private_ones() {
    let (witness, publics) = honest_hop();
    let trace = generate(&witness);
    let height = trace.height();
    let tips = tips_from_trace(&trace);
    let pv = publics.to_public_values(&tips);
    let air = TransferAir::default();

    // -- Control 0: the honest witness satisfies every constraint on every
    // two-row window. Without this, "some constraint fired" would be noise.
    for r in 0..height - 1 {
        let ck = evaluate(&air, &window(&trace, r), &pv, r == 0);
        assert!(
            ck.fired.is_empty(),
            "the honest trace violates {} constraint(s) at window ({r}, {}) — \
             the probe below would be measuring nothing but that",
            ck.fired.len(),
            r + 1
        );
    }

    // -- Where the chain section's assertions stop and the sponge section's
    // begin. `WotsAir` is `eval_chain_section` and nothing else, so the count
    // it raises is the count `TransferAir` raises before constraint 18. (Its
    // *verdict* on a sponge row is meaningless — it evaluates the section with
    // the sponge gate off — but the number of assertions does not depend on
    // the gate.)
    let probe = window(&trace, CHAIN_ROWS);
    let total = evaluate(&air, &probe, &pv, false).seen;
    let chain = evaluate(&WotsAir::default(), &probe, &pv, false).seen;
    assert!(
        chain > 0 && chain < total,
        "chain/sponge boundary is nonsense: {chain} of {total}"
    );
    assert_eq!(
        total - chain,
        SPONGE_ASSERTS,
        "the sponge section no longer raises the {SPONGE_ASSERTS} assertions this test's \
         constraint tally describes — the tally, and probably the expected free set, is stale"
    );
    let sponge_fired = |ck: &Checker| ck.fired.iter().any(|&at| at >= chain);
    let chain_fired = |ck: &Checker| ck.fired.iter().any(|&at| at < chain);

    // -- The sweep.
    let mut free: Vec<(usize, usize)> = Vec::new();
    let mut controls_seen = (false, false);
    for j in 0..SPONGE_ROWS {
        let row = CHAIN_ROWS + j;
        for i in 0..WIDTH {
            // The row under test as `next`: constraints 24 and 25.
            let mut trailing = window(&trace, row - 1);
            let col = lane_col(&trailing[..T_COLS], i);
            trailing[T_COLS + col] += BabyBear::ONE;
            let back = evaluate(&air, &trailing, &pv, false);

            // The row under test as `local`: constraints 20-23.
            let mut leading = window(&trace, row);
            leading[col] += BabyBear::ONE;
            let forward = evaluate(&air, &leading, &pv, false);

            // -- Control 1: the column really is a permutation input. The
            // permutation's own constraints must object to the change on the
            // row that owns it. If they do not, the probe moved a column
            // nothing reads and every FREE below is a false negative.
            assert!(
                chain_fired(&forward),
                "sponge row {j} lane {i}: perturbing column {col} did not disturb the \
                 permutation — the probe is not touching a permutation input lane"
            );

            let (as_next, as_local) = (sponge_fired(&back), sponge_fired(&forward));
            if as_next || as_local {
                // -- Control 3: the tie came from the side that owns this row.
                let is_start = START_ROWS.contains(&j);
                assert_eq!(
                    (as_local, as_next),
                    (is_start, !is_start),
                    "sponge row {j} lane {i} is pinned from the wrong side of its \
                     transition: (as local, as next) = ({as_local}, {as_next}), and row {j} \
                     {} a start row",
                    if is_start { "is" } else { "is not" }
                );

                // -- Control 2 (the sanity control the audit asked for): a lane
                // known to be pinned must come back PINNED, and from the window
                // it is pinned in. Lane 0 of sponge row 0 is tied to the public
                // asset id by constraint 23, which reads the row as `local`.
                if (j, i) == (0, 0) {
                    assert!(
                        as_local,
                        "the asset lane is pinned by constraint 23 but the probe did not \
                         see it — the harness is blind and every FREE is a false negative"
                    );
                    controls_seen.0 = true;
                }
                // Lane 8 of sponge row 1 is the first capacity element carried
                // in by constraint 24, which reads the row as `next`.
                if (j, i) == (1, N) {
                    assert!(
                        as_next,
                        "the capacity carry is pinned by constraint 24 but the probe did \
                         not see it — the harness is blind on the transition side"
                    );
                    controls_seen.1 = true;
                }
            } else {
                free.push((j, i));
            }
        }
    }
    assert_eq!(
        controls_seen,
        (true, true),
        "a known-pinned lane came back FREE: the two sanity controls are the whole \
         basis for trusting the rest of this measurement"
    );

    // -- The expectation, lane by lane.
    let expected: Vec<(usize, usize)> = EXPECTED_FREE
        .iter()
        .flat_map(|&(row, lo, hi, _)| (lo..hi).map(move |i| (row, i)))
        .collect();
    assert_eq!(
        expected.len(),
        HAND_TRACED_FREE,
        "the table in this file no longer spells out {HAND_TRACED_FREE} lanes"
    );

    let describe = |(j, i): (usize, usize)| -> String {
        let what = EXPECTED_FREE
            .iter()
            .find(|&&(row, lo, hi, _)| row == j && (lo..hi).contains(&i))
            .map_or("NOT IN THE EXPECTED SET", |&(_, _, _, what)| what);
        format!("  sponge row {j:>2} lane {i:>2}  {what}")
    };
    let missing: Vec<String> = expected
        .iter()
        .filter(|p| !free.contains(p))
        .map(|&p| describe(p))
        .collect();
    let extra: Vec<String> = free
        .iter()
        .filter(|p| !expected.contains(p))
        .map(|&p| describe(p))
        .collect();

    assert!(
        extra.is_empty(),
        "UNTIED LANES: {} sponge lane(s) no constraint reads, which the tie table is \
         supposed to pin. Each one is a value a prover may choose freely:\n{}",
        extra.len(),
        extra.join("\n")
    );
    assert!(
        missing.is_empty(),
        "{} lane(s) expected free came back pinned. Either the hand-traced set is wrong \
         or this probe over-reports:\n{}",
        missing.len(),
        missing.join("\n")
    );
    assert_eq!(
        free.len(),
        HAND_TRACED_FREE,
        "free-lane count moved: {} free of {} lanes across {SPONGE_ROWS} sponge rows",
        free.len(),
        SPONGE_ROWS * WIDTH
    );
}
