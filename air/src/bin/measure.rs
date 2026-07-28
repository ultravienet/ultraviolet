//! The finished WOTS+ circuit, measured — replacing Phase A's projection.
//!
//! Phase A measured a bare Poseidon2 AIR (0.040 s / 137.7 KB / 111 MB) and
//! projected from it. This measures the real thing: one full WOTS+ verification,
//! chain constraints and all, in both the standard and hiding configurations.
//!
//! Run: `/usr/bin/time -l cargo run --release -p uv-air --bin measure`

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;
use uv_air::wots_air::{CHAIN_ROWS, NUM_COLS};
use uv_air::{prove, trace, wots};

fn main() {
    let perm = wots::permutation();
    let seed = [42u8; 32];
    let pk = wots::public_key(&perm, &seed);

    let mut s = [BabyBear::ZERO; wots::WIDTH];
    s[0] = BabyBear::from_u32(1234);
    perm.permute_mut(&mut s);
    let mut msg = [BabyBear::ZERO; wots::N];
    msg.copy_from_slice(&s[..wots::N]);

    let sig = wots::sign(&perm, &seed, &msg);
    assert!(wots::verify(&perm, &pk, &msg, &sig), "host must verify");

    // Warm-up: the first proof in a process pays for allocator growth, page
    // faults, and cold caches. Timing it would flatter whichever circuit ran
    // second — and did: the wider transfer circuit read as *faster* than the
    // signature circuit until this existed, which is not physically possible.
    // Prove once and discard before any measurement.
    {
        let cfg = prove::config();
        let _ = prove::prove(&cfg, &msg, &sig);
    }

    let only = std::env::var("UV_MEASURE").unwrap_or_default();
    let do_sig = only.is_empty() || only == "signature";
    let do_transfer = only.is_empty() || only.starts_with("transfer");
    // Peak memory is a *process* high-water mark. Proving both configurations
    // in one process reports their union, which is neither one's cost — the
    // hiding config alone turned out to need far more than the pair suggested
    // when measured on a phone. `transfer-standard` / `transfer-hiding` run one
    // configuration per process so the memory figure belongs to that one.
    let do_std = only != "transfer-hiding";
    let do_hiding = only != "transfer-standard";

    let t0 = Instant::now();
    let tr = trace::generate(&msg, &sig);
    let gen_s = t0.elapsed().as_secs_f64();
    let (rows, cols) = (tr.height(), tr.width());

    println!("\n=== the real WOTS+ circuit ===");
    println!(
        "chains        : {} x {} steps = {CHAIN_ROWS} rows of work",
        wots::CHAINS,
        wots::W - 1
    );
    println!("trace         : {rows} rows x {cols} cols  (generated in {gen_s:.3} s)");
    println!("columns check : {} expected", NUM_COLS);

    let cfg = prove::config();
    if do_sig {
        // Standard. Timed through the public wrapper, so the numbers include what
        // consensus actually pays: trace generation and public-value construction
        // on the prove side; the compress check and pv rebuild on the verify side.
        let t0 = Instant::now();
        let proof = prove::prove(&cfg, &msg, &sig);
        let prove_s = t0.elapsed().as_secs_f64();
        let kb = bincode_len(&proof);
        let t0 = Instant::now();
        prove::verify(&cfg, &proof, &msg, &pk).expect("verify");
        let verify_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // Hiding.
        let hcfg = prove::hiding_config();
        let t0 = Instant::now();
        let hproof = prove::prove_hiding(&hcfg, &msg, &sig);
        let hprove_s = t0.elapsed().as_secs_f64();
        let hkb = bincode_len(&hproof);
        let t0 = Instant::now();
        prove::verify_hiding(&hcfg, &hproof, &msg, &pk).expect("verify hiding");
        let hverify_ms = t0.elapsed().as_secs_f64() * 1000.0;

        println!(
            "\n{:<14} {:>10} {:>11} {:>11}",
            "config", "prove s", "proof KB", "verify ms"
        );
        println!(
            "{:<14} {prove_s:>10.3} {kb:>11.1} {verify_ms:>11.2}",
            "standard"
        );
        println!(
            "{:<14} {hprove_s:>10.3} {hkb:>11.1} {hverify_ms:>11.2}",
            "hiding (ZK)"
        );

        println!("\n=== versus the zkVM it replaces ===");
        println!("SP1 today  : 124.000 s   1242.0 KB   9.67 GB peak RSS");
        println!("this        : {prove_s:>7.3} s   {kb:>6.1} KB   (peak RSS: /usr/bin/time -l)");
        println!(
            "             -> {:.0}x faster, {:.1}x smaller proof",
            124.0 / prove_s.max(1e-9),
            1242.0 / kb.max(1e-9)
        );
        println!(
            "hiding      -> {:.0}x faster than SP1, and actually zero-knowledge,",
            124.0 / hprove_s.max(1e-9)
        );
        println!("               which SP1's raw STARK is not at any price.");
        println!(
            "\nZK costs {:.2}x prove time and {:.2}x proof size over standard.",
            hprove_s / prove_s.max(1e-9),
            hkb / kb.max(1e-9)
        );
        println!(
            "\nThe proof binds message and public key: digits and tips are public\n\
         values (constraints 13-17), and verification includes the wrapper's\n\
         host-side compress(tips) == pk check. Proof size includes the tips."
        );
    }

    // ---- The full transfer circuit: one complete money-path hop ----
    use uv_air::transfer_trace::{NoteOpening, TransferWitness};
    let limbs = |v: u64| -> [BabyBear; 4] {
        core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
    };
    let open = |tag: u32, v: u64| -> NoteOpening {
        let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
        NoteOpening {
            amount_limbs: limbs(v),
            owner_pk: wots::public_key(&perm, &[tag as u8; 32]),
            anchor: uv_air::sponge::hash(uv_air::sponge::Domain::SpendAnchor, &nk),
            nullifier_key: nk,
            randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
        }
    };
    let commitment = |o: &NoteOpening, asset: &[BabyBear; 8]| {
        let mut p = Vec::new();
        p.extend_from_slice(asset);
        p.extend_from_slice(&o.amount_limbs);
        p.extend_from_slice(&o.owner_pk);
        p.extend_from_slice(&o.anchor);
        p.extend_from_slice(&o.randomness);
        uv_air::sponge::hash(uv_air::sponge::Domain::Note, &p)
    };
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = open(41, 100);
    let outs = [open(42, 60), open(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);
    let publics = uv_air::prove::TransferPublics::new(
        input_commitment,
        uv_air::sponge::hash(uv_air::sponge::Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    // The witness must sign the statement's own message, which the constructor
    // derived — not a message chosen alongside it.
    let msg = *publics.msg();
    // Sign with the INPUT NOTE's seed — constraint 25 ties compress(tips)
    // into the commitment opening, so a foreign key cannot verify (that
    // mistake was made here once, and the circuit caught it).
    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
        sig: wots::sign(&perm, &[41u8; 32], &msg),
    };

    if !do_transfer {
        return;
    }
    let mut tprove_s = f64::NAN;
    let mut tkb = f64::NAN;
    let mut tverify_ms = f64::NAN;
    if do_std {
        let t0 = Instant::now();
        let tproof = prove::prove_transfer(&cfg, &witness, &publics);
        tprove_s = t0.elapsed().as_secs_f64();
        tkb = bincode_len(&tproof);
        let t0 = Instant::now();
        prove::verify_transfer(&cfg, &tproof, &publics).expect("transfer verify");
        tverify_ms = t0.elapsed().as_secs_f64() * 1000.0;
    }

    let mut htprove_s = f64::NAN;
    let mut htkb = f64::NAN;
    let mut htverify_ms = f64::NAN;
    if do_hiding {
        let hcfg2 = prove::hiding_config();
        let t0 = Instant::now();
        let htproof = prove::prove_transfer_hiding(&hcfg2, &witness, &publics);
        htprove_s = t0.elapsed().as_secs_f64();
        htkb = bincode_len(&htproof);
        let t0 = Instant::now();
        prove::verify_transfer_hiding(&hcfg2, &htproof, &publics).expect("hiding transfer verify");
        htverify_ms = t0.elapsed().as_secs_f64() * 1000.0;
    }

    println!("\n=== the full transfer circuit (one complete hop) ===");
    println!("commitment openings + nullifier + conservation + WOTS+, one table, 1024 x 457");
    println!(
        "{:<14} {:>10} {:>11} {:>11}",
        "config", "prove s", "proof KB", "verify ms"
    );
    if do_std {
        println!(
            "{:<14} {tprove_s:>10.3} {tkb:>11.1} {tverify_ms:>11.2}",
            "standard"
        );
    }
    if do_hiding {
        println!(
            "{:<14} {htprove_s:>10.3} {htkb:>11.1} {htverify_ms:>11.2}",
            "hiding (ZK)"
        );
    }
    println!(
        "peak RSS      : {:.0} MB (self-reported{})",
        peak_rss_mb(),
        if do_std && do_hiding {
            ", both configs in one process"
        } else {
            ", this config alone"
        }
    );
    if do_std && do_hiding {
        println!(
            "\nvs SP1's 124 s / 1242 KB per hop: {:.0}x faster, {:.1}x smaller —\n\
             and this hop includes what SP1's never did: a sound message binding\n\
             and (in the hiding config) actual zero-knowledge.",
            124.0 / tprove_s.max(1e-9),
            1242.0 / tkb.max(1e-9)
        );
    }
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
