//! Money-path proving benchmark: the proof-native transfer circuit.
//!
//! There is one circuit to measure — the anchor-preimage transfer
//! (`authproto_air`). `UV_MEASURE=standard|hiding` runs
//! one config; the default runs both. The **hiding config is the payment
//! format**: the witness (the nullifier key) is fund-critical, so zero-knowledge
//! is not optional here.

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use uv_air::prove;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

fn main() {
    let only = std::env::var("UV_MEASURE").unwrap_or_default();
    let do_std = only.is_empty() || only == "standard";
    let do_hiding = only.is_empty() || only == "hiding";

    // One honest hop: input of 100 spent into 60 + 40, built exactly as the
    // circuit's differential tests build it.
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
    let publics = prove::TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    let msg = *publics.msg();
    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };

    println!("=== money path: proof-native transfer (spec/99 `[PROOF-AUTH]`) ===");
    println!(
        "commitment openings + nullifier + conservation + anchor-preimage auth; trace {} x {}",
        uv_air::authproto_air::HEIGHT,
        uv_air::authproto_air::NUM_COLS
    );
    println!(
        "{:<14} {:>10} {:>11} {:>11}",
        "config", "prove s", "proof KB", "verify ms"
    );

    if do_std {
        let cfg = prove::config();
        let t0 = Instant::now();
        let proof = prove::prove_authproto(&cfg, &witness, &publics);
        let s = t0.elapsed().as_secs_f64();
        let kb = bincode_len(&proof.stark);
        let t0 = Instant::now();
        prove::verify_authproto(&cfg, &proof, &publics).expect("verify");
        let vms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("{:<14} {s:>10.3} {kb:>11.1} {vms:>11.2}", "standard");
    }
    if do_hiding {
        let hcfg = prove::hiding_config();
        let t0 = Instant::now();
        let proof = prove::prove_authproto_hiding(&hcfg, &witness, &publics);
        let s = t0.elapsed().as_secs_f64();
        let kb = bincode_len(&proof.stark);
        let t0 = Instant::now();
        prove::verify_authproto_hiding(&hcfg, &proof, &publics).expect("hiding verify");
        let vms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("{:<14} {s:>10.3} {kb:>11.1} {vms:>11.2}", "hiding (ZK)");
    }
    println!("peak RSS      : {:.0} MB (self-reported)", peak_rss_mb());
    println!("\nThe hiding config is the payment format.");
}

/// Peak resident set size of *this* process, in MB.
///
/// Self-reported via `getrusage` rather than `/usr/bin/time`, so the number is
/// available on every target — including inside an iOS process, where there is
/// no shell to wrap the command in.
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
    let rc = unsafe { getrusage(0, &mut u) };
    if rc != 0 {
        return f64::NAN;
    }
    // Darwin reports ru_maxrss in bytes (Linux uses kilobytes).
    #[cfg(target_vendor = "apple")]
    let bytes = u.ru_maxrss as f64;
    #[cfg(not(target_vendor = "apple"))]
    let bytes = u.ru_maxrss as f64 * 1024.0;
    bytes / 1_048_576.0
}

fn bincode_len<T: serde::Serialize>(v: &T) -> f64 {
    bincode::serialize(v).map(|b| b.len()).unwrap_or(0) as f64 / 1024.0
}
