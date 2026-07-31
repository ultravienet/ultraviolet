//! `[ACC]` Part 1 cost measurement: what a taller money-path trace costs.
//!
//! **The rule this feeds is recorded in `spec/99-OPEN-PROBLEMS.md` under `[ACC]`,
//! and it was written before this binary existed.** Read it first; a threshold
//! chosen after seeing the number is not a threshold.
//!
//! ## What is being measured, and why a padded trace is the right proxy
//!
//! `[ACC]` Part 1 has each hop prove in-circuit that its record is the first
//! occurrence of its nullifier in the accumulator `A_h`: one Merkle inclusion
//! path for the winner, plus — for non-inclusion — one inclusion path for the
//! predecessor leaf in an indexed tree, plus a key range check. At 2^24 records
//! that is ~48 rows on top of today's 15, so the trace goes 16 → 64.
//!
//! **Every row of this AIR is one Poseidon2 permutation**: a Merkle compression
//! and a sponge absorb cost the same row. So a 64-row trace of the *existing*
//! circuit has the shape Part 1 will have, at the same column count, and its
//! prover cost is what the rule asks about.
//!
//! **What this proxy does not do**, said plainly rather than left to be
//! discovered: it says nothing about whether Merkle constraints over this layout
//! are *sound*, and nothing about the extra columns a range check would want. It
//! is a cost measurement. A green number here means "Part 1 is affordable", never
//! "Part 1 works".
//!
//! ## How the taller trace is built without touching a consensus file
//!
//! `air/src` constraint code is under a mutation-sweep gate, so this binary adds
//! no production code and changes no constraint. `authproto_air::generate`
//! already emits row 15 as a **padding row** (rows 0..14 are the five sponges;
//! `SPONGE_ROWS` is 15). A taller trace here is the real generated trace with
//! that real padding row replicated — so every row is one the production
//! generator produced, not one this file invented.
//!
//! Proofs are **verified**, not merely produced. `prove::verify_authproto` pins
//! trace height deliberately (`air/tests/trace_height_is_pinned.rs`), so this
//! calls `p3_uni_stark::verify` directly with the same config, AIR and public
//! values. A prove time for a proof that does not verify is a time for computing
//! the wrong thing.
//!
//! ```text
//! cargo run --release -p uv-air --bin acc-shape
//! UV_ACC_HEIGHTS=16,64 UV_ACC_MODE=hiding cargo run --release -p uv-air --bin acc-shape
//! ```
//!
//! Run **one configuration per process** when the memory column matters: peak
//! RSS is a process high-water mark, so proving standard and hiding together
//! reports the union, which is neither one's cost (the journal has the on-device numbers).

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove as p3_prove, verify as p3_verify};

use uv_air::authproto_air::{self, AuthProtoAir, NUM_COLS, NUM_PUBLIC_VALUES};
use uv_air::prove;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

/// The real trace, with its real padding row replicated to `height`.
fn padded_trace(w: &TransferWitness, height: usize) -> RowMajorMatrix<BabyBear> {
    let base = authproto_air::generate(w);
    let base_h = base.height();
    assert!(
        height.is_power_of_two(),
        "a STARK trace height must be a power of two"
    );
    assert!(
        height >= base_h,
        "height {height} would truncate the {base_h} generated rows, which would \
         measure a different circuit rather than a taller one"
    );
    assert_eq!(base.width(), NUM_COLS);

    let pad = base_h - 1; // row 15, emitted by `generate` as padding
    let mut values = Vec::with_capacity(height * NUM_COLS);
    values.extend_from_slice(&base.values);
    let pad_row: Vec<BabyBear> = base.values[pad * NUM_COLS..(pad + 1) * NUM_COLS].to_vec();
    for _ in base_h..height {
        values.extend_from_slice(&pad_row);
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

/// Peak RSS of this process in MB, by the same mechanism `measure.rs` and the
/// iOS harness use, so all three numbers are comparable.
fn peak_rss_mb() -> f64 {
    #[repr(C)]
    #[derive(Default)]
    struct Rusage {
        ru_utime: [i64; 2],
        ru_stime: [i64; 2],
        ru_maxrss: i64,
        rest: [i64; 13],
    }
    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }
    let mut u = Rusage::default();
    // SAFETY: getrusage writes a fixed-layout struct we own; RUSAGE_SELF = 0.
    if unsafe { getrusage(0, &mut u) } != 0 {
        return f64::NAN;
    }
    #[cfg(target_vendor = "apple")]
    let bytes = u.ru_maxrss as f64;
    #[cfg(not(target_vendor = "apple"))]
    let bytes = u.ru_maxrss as f64 * 1024.0;
    bytes / 1_048_576.0
}

fn bincode_kb<T: serde::Serialize>(v: &T) -> f64 {
    bincode::serialize(v).map(|b| b.len()).unwrap_or(0) as f64 / 1024.0
}

fn main() {
    let heights: Vec<usize> = std::env::var("UV_ACC_HEIGHTS")
        .unwrap_or_else(|_| "16,32,64,128,256".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let mode = std::env::var("UV_ACC_MODE").unwrap_or_default();
    let do_std = mode.is_empty() || mode == "standard";
    let do_hiding = mode.is_empty() || mode == "hiding";

    // One honest hop: 100 in, 60 + 40 out — built exactly as `measure.rs` builds
    // it, so the 16-row row below must reproduce the published figure. That
    // agreement is the control saying this harness measures the same thing.
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
    // `NoteOpening::preimage` is private, so the commitment is spelled out the
    // way `measure.rs` spells it — same order, same domain. Two copies of this
    // is a smell, and the reason it is tolerated is that the alternative is
    // widening a consensus crate's API for a benchmark.
    let commitment = |o: &NoteOpening, asset: &[BabyBear; 8]| {
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
        prove::TransferPublics::new(input_commitment, nullifier, out0, out1, prev_history, asset);
    let msg = *publics.msg();
    let w = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };

    // The 56 public values, in the layout `authproto_air`'s PV_* constants fix.
    // Built here from the same digests the publics were built from rather than
    // read back out of `TransferPublics`, which deliberately exposes no getters.
    let mut pv: Vec<BabyBear> = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for part in [
        &input_commitment,
        &nullifier,
        &out0,
        &out1,
        &prev_history,
        &asset,
        &msg,
    ] {
        pv.extend_from_slice(part.as_slice());
    }
    assert_eq!(pv.len(), NUM_PUBLIC_VALUES);

    println!("=== [ACC] Part 1 shape cost: money-path trace at increasing heights ===");
    println!("trace width {NUM_COLS} columns; one row = one Poseidon2 permutation");
    println!("rule: spec/99 `[ACC]`, recorded before this ran");
    println!();
    println!(
        "{:>6}  {:<9} {:>9} {:>10} {:>10} {:>10}",
        "height", "config", "prove s", "proof KB", "verify ms", "peak MB"
    );

    let mut failures = 0;
    for &h in &heights {
        let trace = padded_trace(&w, h);
        for (label, hiding) in [("standard", false), ("hiding", true)] {
            if (label == "standard" && !do_std) || (label == "hiding" && !do_hiding) {
                continue;
            }
            let air = AuthProtoAir::default();
            let (s, kb, vms, ok) = if hiding {
                let cfg = prove::hiding_config();
                let t = Instant::now();
                let proof = p3_prove(cfg.inner(), &air, trace.clone(), &pv);
                let s = t.elapsed().as_secs_f64();
                let kb = bincode_kb(&proof);
                let t = Instant::now();
                let ok = p3_verify(cfg.inner(), &air, &proof, &pv).is_ok();
                (s, kb, t.elapsed().as_secs_f64() * 1000.0, ok)
            } else {
                let cfg = prove::config();
                let t = Instant::now();
                let proof = p3_prove(cfg.inner(), &air, trace.clone(), &pv);
                let s = t.elapsed().as_secs_f64();
                let kb = bincode_kb(&proof);
                let t = Instant::now();
                let ok = p3_verify(cfg.inner(), &air, &proof, &pv).is_ok();
                (s, kb, t.elapsed().as_secs_f64() * 1000.0, ok)
            };
            if !ok {
                failures += 1;
            }
            println!(
                "{h:>6}  {label:<9} {s:>9.4} {kb:>10.1} {vms:>10.2} {:>10.0}{}",
                peak_rss_mb(),
                if ok { "" } else { "   <-- VERIFY FAILED" }
            );
        }
    }

    println!();
    println!("The 16-row row is the control: it must reproduce the published figure.");
    if failures > 0 {
        println!(
            "{failures} row(s) FAILED TO VERIFY. Those timings are void -- a padded \n\
             trace that does not satisfy the constraints is not this circuit, taller."
        );
        std::process::exit(1);
    }
    println!("Every proof above verified, so every timing is for a real proof.");
}
