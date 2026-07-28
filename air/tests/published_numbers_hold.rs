//! A guard on the numbers this project publishes.
//!
//! **Why this exists.** We measured the prover, put the figures on the website
//! and in four spec files, and then changed the prover's hot path for security
//! reasons — swapping the blinding generator from a fast insecure one to a
//! cryptographic one — without re-measuring. The numbers happened to survive
//! (re-measured: the change costs nothing detectable, because proving is
//! dominated by transforms and hashing, not by drawing random field elements).
//! But nothing would have told us if they hadn't.
//!
//! ## What is asserted, and why in this shape
//!
//! **Proof sizes, exactly.** These are deterministic — they do not depend on
//! the machine, the load, or the weather — and they are what actually pins the
//! wire format. A change here is either a deliberate format change or a bug,
//! and either way somebody should have to update this file on purpose.
//!
//! **Timing as a ratio, not a duration.** A CI runner is slower and far noisier
//! than a development machine, so an absolute time bound either flakes or is so
//! loose it catches nothing. The ratio between the two configurations cancels
//! machine speed almost entirely: hiding costs about 2.8× standard today, and a
//! change that made hiding twice as expensive would show up as ~5.6× on any
//! hardware. That is the regression this can actually catch.
//!
//! **Absolute ceilings only in release builds.** CI runs the test suite
//! unoptimized, where a proof takes *157× longer* than on a development
//! machine — 11 s against 0.07 s, measured. Any absolute bound meaningful in
//! release is absurd in debug and vice versa, so the wall-clock assertions are
//! skipped when unoptimized. The ratio is not skipped, because it does not
//! care: across that same 157× gap it read 2.59× against the Mac's 2.8×, which
//! is the whole argument for expressing the guard as a ratio.
//!
//! ## What this does not do
//!
//! It does not check memory. Peak RSS is a process high-water mark and depends
//! on the allocator, which differs between platforms enough that a bound tight
//! enough to be useful would flake — the phone needs 279–284 MB for the hiding
//! configuration where the Mac needs 114 MB, and we could not explain the gap.
//! It also cannot check the device numbers, because the device is not here.
//! Those stay a manual measurement; this guard's job is to make it obvious when
//! they are due to be redone.

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use uv_air::prove;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};
use uv_air::wots;

/// Published in `docs/benchmarks.html`, `spec/04-PROOFS.md`, and the README.
const PUBLISHED_STANDARD_BYTES: usize = 162_132;
const PUBLISHED_HIDING_BYTES: usize = 213_008;

/// Hiding costs ~2.8x standard. Allow generous room for a noisy runner, but not
/// so much that doubling the cost of the payment format slips through.
const MAX_HIDING_TO_STANDARD_RATIO: f64 = 6.0;

/// Catastrophe ceilings, not drift detectors. A payment must not take seconds.
const MAX_STANDARD_SECS: f64 = 5.0;
const MAX_HIDING_SECS: f64 = 15.0;

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

fn one_hop() -> (TransferWitness, prove::TransferPublics) {
    let perm = wots::permutation();
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(&perm, 41, 100);
    let outs = [opening(&perm, 42, 60), opening(&perm, 43, 40)];
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

/// The wire format is fixed. A change here must be deliberate.
#[test]
fn proof_sizes_are_exactly_what_we_publish() {
    let (w, p) = one_hop();

    let std_bytes = bincode::serialize(&prove::prove_transfer(&prove::config(), &w, &p))
        .expect("serialize")
        .len();
    let hid_bytes = bincode::serialize(&prove::prove_transfer_hiding(
        &prove::hiding_config(),
        &w,
        &p,
    ))
    .expect("serialize")
    .len();

    assert_eq!(
        std_bytes, PUBLISHED_STANDARD_BYTES,
        "standard proof size changed. If deliberate, update this constant AND every \
         published figure: docs/benchmarks.html, docs/index.html, README.md, \
         spec/04-PROOFS.md, spec/99-OPEN-PROBLEMS.md, demo/ios.md"
    );
    assert_eq!(
        hid_bytes, PUBLISHED_HIDING_BYTES,
        "hiding proof size changed -- and hiding is the payment format. If deliberate, \
         update this constant AND every published figure."
    );
}

/// Catch a change that makes the payment format dramatically more expensive,
/// without depending on how fast the machine running this happens to be.
#[test]
fn hiding_has_not_become_dramatically_more_expensive_than_standard() {
    let (w, p) = one_hop();

    // Warm up: the first proof in a process pays for allocator growth and cold
    // caches, and timing it would flatter whichever ran second. This harness
    // made exactly that mistake once.
    let _ = prove::prove_transfer(&prove::config(), &w, &p);

    let cfg = prove::config();
    let t = Instant::now();
    let _ = prove::prove_transfer(&cfg, &w, &p);
    let standard = t.elapsed().as_secs_f64();

    let hcfg = prove::hiding_config();
    let _ = prove::prove_transfer_hiding(&hcfg, &w, &p);
    let t = Instant::now();
    let _ = prove::prove_transfer_hiding(&hcfg, &w, &p);
    let hiding = t.elapsed().as_secs_f64();

    let ratio = hiding / standard;
    println!("standard {standard:.3}s, hiding {hiding:.3}s, ratio {ratio:.2}x");

    // Wall-clock bounds mean nothing in an unoptimized build; the ratio still
    // does, so it is checked either way.
    if cfg!(debug_assertions) {
        println!(
            "unoptimized build: wall-clock ceilings skipped, ratio still enforced. \
             Published figures come from `cargo run --release`."
        );
    } else {
        assert!(
            standard < MAX_STANDARD_SECS,
            "a standard proof took {standard:.3}s; something is catastrophically wrong"
        );
        assert!(
            hiding < MAX_HIDING_SECS,
            "a hiding proof took {hiding:.3}s; something is catastrophically wrong"
        );
    }
    assert!(
        ratio < MAX_HIDING_TO_STANDARD_RATIO,
        "hiding now costs {ratio:.2}x standard, against ~2.8x when the published \
         numbers were measured. Re-measure on a quiet machine and on a phone, then \
         update the published figures -- or find out what regressed."
    );
}
