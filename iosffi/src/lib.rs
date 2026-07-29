//! One C function so an iOS app can measure the prover on real silicon.
//!
//! Everything the simulator could tell us, it already has. What it cannot tell
//! us is speed on an A-series chip: the simulator runs arm64 natively on the
//! development Mac. This exists so the number comes from the phone.

mod call;

use std::ffi::CString;
use std::os::raw::c_char;
use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use uv_air::prove;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

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
    // SAFETY: fixed-layout struct we own; RUSAGE_SELF = 0. Darwin reports
    // ru_maxrss in bytes.
    if unsafe { getrusage(0, &mut u) } != 0 {
        return f64::NAN;
    }
    u.ru_maxrss as f64 / 1_048_576.0
}

fn bincode_kb<T: serde::Serialize>(v: &T) -> f64 {
    bincode::serialize(v).map(|b| b.len()).unwrap_or(0) as f64 / 1024.0
}

fn limbs(v: u64) -> [BabyBear; 4] {
    core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
}

fn opening(tag: u32, v: u64) -> NoteOpening {
    let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
    NoteOpening {
        amount_limbs: limbs(v),
        anchor: sponge::hash(Domain::SpendAnchor, &nk),
        nullifier_key: nk,
        randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
    }
}

fn commitment(o: &NoteOpening, asset: &[BabyBear; 8]) -> [BabyBear; 8] {
    let mut p = Vec::new();
    p.extend_from_slice(asset);
    p.extend_from_slice(&o.amount_limbs);
    p.extend_from_slice(&o.anchor);
    p.extend_from_slice(&o.randomness);
    sponge::hash(Domain::Note, &p)
}

/// Prove one complete payment hop `runs` times and report timings.
///
/// The first proof in a process pays for allocator growth and cold caches, so
/// one warm-up runs before anything is timed — the same discipline the desktop
/// harness uses, for the same reason.
///
/// `mode` selects which circuit runs: 1 standard only, 2 hiding only, anything
/// else both. Peak memory is a *process* high-water mark, so running both in one
/// process reports their union and not either one — the desktop harness isolates
/// them for exactly this reason, and a memory number is only comparable if this
/// one does too. Hiding alone is the number that matters, because hiding is the
/// payment format.
///
/// # Safety
/// The returned pointer must be freed with [`uv_free`].
#[no_mangle]
pub extern "C" fn uv_measure(runs: u32, mode: u32) -> *mut c_char {
    let do_std = mode != 2;
    let do_hid = mode != 1;
    // Read the high-water mark before any proving, so the report can separate
    // what the prover costs from what the host app already cost. Inside an iOS
    // app that baseline is UIKit and the frameworks it drags in, which is not
    // ours and would otherwise inflate the number we publish.
    let rss_before = peak_rss_mb();
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(41, 100);
    let outs = [opening(42, 60), opening(43, 40)];

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

    let mut out = String::new();
    out.push_str(&format!(
        "threads {}\n",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    ));

    if do_std {
        let cfg = prove::config();
        // Warm-up, discarded.
        let _ = prove::prove_authproto(&cfg, &witness, &publics);
        for i in 0..runs.max(1) {
            let t0 = Instant::now();
            let p = prove::prove_authproto(&cfg, &witness, &publics);
            let secs = t0.elapsed().as_secs_f64();
            let t0 = Instant::now();
            let ok = prove::verify_authproto(&cfg, &p, &publics).is_ok();
            let vms = t0.elapsed().as_secs_f64() * 1000.0;
            out.push_str(&format!(
                "run {}: standard {:.3}s verify {:.2}ms ok={} size {:.1} KB\n",
                i + 1,
                secs,
                vms,
                ok,
                bincode_kb(&p)
            ));
        }
    }

    if do_hid {
        let hcfg = prove::hiding_config();
        let _ = prove::prove_authproto_hiding(&hcfg, &witness, &publics);
        for i in 0..runs.max(1) {
            let t0 = Instant::now();
            let p = prove::prove_authproto_hiding(&hcfg, &witness, &publics);
            let secs = t0.elapsed().as_secs_f64();
            let t0 = Instant::now();
            let ok = prove::verify_authproto_hiding(&hcfg, &p, &publics).is_ok();
            let vms = t0.elapsed().as_secs_f64() * 1000.0;
            out.push_str(&format!(
                "run {}: hiding {:.3}s verify {:.2}ms ok={} size {:.1} KB\n",
                i + 1,
                secs,
                vms,
                ok,
                bincode_kb(&p)
            ));
        }
    }
    let peak = peak_rss_mb();
    out.push_str(&format!(
        "RSS before proving {:.0} MB, peak {:.0} MB, prover share {:.0} MB\n",
        rss_before,
        peak,
        peak - rss_before
    ));

    CString::new(out).unwrap_or_default().into_raw()
}

/// # Safety
/// `p` must come from [`uv_measure`] and be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn uv_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}
