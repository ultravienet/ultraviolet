//! Padding rows are free, and that freedom must not reach the statement.
//!
//! The transfer trace is 1,024 rows because that is the next power of two above
//! 1,005 chain rows plus 18 sponge rows. Row 1,023 is left over. Many of its
//! cells are genuinely unconstrained — `chain_in`, `chain_out`, `sel`, `digit`,
//! `bits`, `acc`, and the entire amount bus, because constraint 27's gate stops
//! at the last sponge row and deliberately does not carry into padding.
//!
//! **Measured, not assumed:** of the cells an audit listed as free on the
//! padding row, only the amount bus actually is. `SEL`, `DIGIT`, `BITS`, `ACC`,
//! `CHAIN_IN` and `CHAIN_OUT` all still refuse garbage there — they feed the
//! permutation or are tied to each other by constraints that are not gated on
//! the sponge register. The padding row is considerably more constrained than
//! it was believed to be, which is the pleasant direction to be wrong in.
//!
//! The bus is free because constraint 27's gate deliberately stops at the last
//! sponge row rather than carrying into padding.
//!
//! That is *sound*, but by an argument with three legs, not by a constraint:
//!
//! 1. the trace height is exactly 1,024;
//! 2. the `SP` and `OH` registers are fully determined by induction, so they are
//!    zero on the padding row, which gates off every constraint that reads the
//!    free cells;
//! 3. there is no `when_last_row` constraint anywhere in this crate, and
//!    `is_transition` vanishes on the final row, so nothing transitions out of
//!    padding.
//!
//! **Leg one is what an adversarial reader forged a payment through earlier
//! today** — the height was assumed rather than checked. Legs two and three are
//! just as unwritten, so this test pins the conclusion instead of the reasoning:
//! fill every free padding cell with garbage and require that the proof still
//! verifies and the statement is byte-identical.
//!
//! What it does not show: that the padding row is *unreachable* by some other
//! route, or anything about a height other than 1,024. It shows that this
//! freedom exists and cannot influence what a proof says.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use p3_uni_stark::{prove as p3_prove, verify as p3_verify};
use uv_air::prove::{self, TransferPublics};
use uv_air::sponge::{self, Domain};
use uv_air::transfer_air::{TransferAir, NUM_COLS};
use uv_air::transfer_trace::{self, NoteOpening, TransferWitness};
use uv_air::wots;
use uv_air::wots_air::{ACC, BITS, CHAIN_IN, CHAIN_OUT, DIGIT, SEL};

fn limbs(v: u64) -> [BabyBear; 4] {
    core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
}

fn opening(perm: &p3_baby_bear::Poseidon2BabyBear<16>, tag: u32, v: u64) -> NoteOpening {
    let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
    NoteOpening {
        amount_limbs: limbs(v),
        owner_pk: wots::public_key(perm, &[tag as u8; 32]),
        anchor: sponge::hash(Domain::SpendAnchor, &nk),
        nullifier_key: nk,
        randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
    }
}

fn commitment(o: &NoteOpening, asset: &[BabyBear; 8]) -> [BabyBear; 8] {
    let mut p = Vec::new();
    p.extend_from_slice(asset);
    p.extend_from_slice(&o.amount_limbs);
    p.extend_from_slice(&o.owner_pk);
    p.extend_from_slice(&o.anchor);
    p.extend_from_slice(&o.randomness);
    sponge::hash(Domain::Note, &p)
}

fn honest_hop() -> (TransferWitness, TransferPublics) {
    let perm = wots::permutation();
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(&perm, 41, 100);
    let outs = [opening(&perm, 42, 60), opening(&perm, 43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);

    let publics = TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    let msg = *publics.msg();
    let mut s = [BabyBear::ZERO; 16];
    s[0] = BabyBear::from_u32(1234);
    perm.permute_mut(&mut s);

    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
        sig: wots::sign(&perm, &[41u8; 32], &msg),
    };
    (witness, publics)
}

/// The columns the padding row leaves free. Everything else on that row is
/// pinned by induction (`SP`, `OH`, `POS`, `IS_LAST`), by booleanity
/// (`CARRY`, `RBITS`), or by the permutation's own constraints.
fn candidate_groups() -> Vec<(&'static str, Vec<usize>)> {
    vec![
        ("SEL", vec![SEL]),
        ("DIGIT", vec![DIGIT]),
        ("ACC", vec![ACC]),
        ("BITS", (BITS..BITS + 4).collect()),
        ("CHAIN_IN", (CHAIN_IN..CHAIN_IN + 8).collect()),
        ("CHAIN_OUT", (CHAIN_OUT..CHAIN_OUT + 8).collect()),
        (
            "bus (NK/T/amounts)",
            (uv_air::transfer_air::NK..uv_air::transfer_air::CARRY).collect(),
        ),
    ]
}

#[test]
fn garbage_in_the_padding_row_changes_nothing() {
    let (witness, publics) = honest_hop();
    let honest = transfer_trace::generate(&witness);
    let height = honest.height();
    assert_eq!(
        height, 1024,
        "this test is about the padding of a 1,024-row trace"
    );

    let cfg = prove::config();
    let baseline = prove::prove_transfer(&cfg, &witness, &publics);
    let baseline_tips: [wots::Digest; wots::CHAINS] = baseline
        .tips
        .as_slice()
        .try_into()
        .expect("an honest proof has one tip per chain");

    let mut rng = SmallRng::seed_from_u64(0x5EED_0BAD);
    let last = height - 1;
    // Only the bus. The rest of the row turns out to be constrained after all —
    // see the module docs and `report_free_padding_columns`.
    let free: Vec<usize> = (uv_air::transfer_air::NK..uv_air::transfer_air::CARRY).collect();
    assert!(
        !free.is_empty(),
        "nothing free means this test proves nothing"
    );

    for round in 0..4 {
        let mut values = honest.values.clone();
        for &c in &free {
            values[last * NUM_COLS + c] = BabyBear::from_u32(rng.random::<u32>() % (1 << 30));
        }
        let dirty = RowMajorMatrix::new(values, NUM_COLS);

        // The statement must be unchanged: the tips are read out of the trace,
        // so if padding could reach them the public values would move.
        let tips = uv_air::trace::tips_from_trace(&dirty);
        assert_eq!(
            tips, baseline_tips,
            "round {round}: padding garbage changed the proof's tips, so it \
             reaches the statement"
        );

        let pv = publics.to_public_values(&tips);
        assert_eq!(
            pv,
            publics.to_public_values(&baseline_tips),
            "round {round}: padding garbage changed the public values"
        );

        // ...and the garbage must still satisfy every constraint. This is the
        // half that tests legs two and three: if anything read those cells, or
        // if a transition ran out of the last row, this would fail.
        let proof = p3_prove(cfg.inner(), &TransferAir::default(), dirty, &pv);
        p3_verify(cfg.inner(), &TransferAir::default(), &proof, &pv)
            .unwrap_or_else(|e| panic!("round {round}: padding garbage broke a constraint: {e:?}"));
    }
}

/// The control. If the harness cannot detect a change to a cell that *is*
/// constrained, then every pass above is a false negative.
#[test]
fn the_probe_can_actually_detect_a_constrained_cell() {
    let (witness, publics) = honest_hop();
    let honest = transfer_trace::generate(&witness);
    let last = honest.height() - 1;

    // `POS` on the padding row is pinned by induction (constraint 13), unlike
    // everything in `free_padding_columns`.
    let mut values = honest.values.clone();
    values[last * NUM_COLS + uv_air::wots_air::POS] += BabyBear::ONE;
    let dirty = RowMajorMatrix::new(values, NUM_COLS);

    let cfg = prove::config();
    let tips = uv_air::trace::tips_from_trace(&dirty);
    let pv = publics.to_public_values(&tips);

    let broke = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let proof = p3_prove(cfg.inner(), &TransferAir::default(), dirty, &pv);
        p3_verify(cfg.inner(), &TransferAir::default(), &proof, &pv).is_err()
    }))
    .unwrap_or(true);

    assert!(
        broke,
        "perturbing a constrained padding cell was accepted — the probe is blind,          so the inertness result above proves nothing"
    );
}

/// Diagnostic, kept because it is how the free set above was established and
/// how it should be re-established if the layout changes. Run with
/// `cargo test -p uv-air --test padding_is_inert report_free -- --ignored --nocapture`.
#[test]
#[ignore]
fn report_free_padding_columns() {
    let (witness, publics) = honest_hop();
    let honest = transfer_trace::generate(&witness);
    let last = honest.height() - 1;
    let cfg = prove::config();

    for (name, cols) in candidate_groups() {
        let mut values = honest.values.clone();
        for &c in &cols {
            values[last * NUM_COLS + c] += BabyBear::from_u32(7);
        }
        let dirty = RowMajorMatrix::new(values, NUM_COLS);
        let tips = uv_air::trace::tips_from_trace(&dirty);
        let pv = publics.to_public_values(&tips);
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = p3_prove(cfg.inner(), &TransferAir::default(), dirty, &pv);
            p3_verify(cfg.inner(), &TransferAir::default(), &proof, &pv).is_ok()
        }))
        .unwrap_or(false);
        println!("{name:22} free={ok}");
    }
}
