//! Attacker-chosen bytes, in bulk. **The first thing here that generates an
//! input nobody chose.**
//!
//! Every other discovery mechanism in this repository replays an input a human
//! picked: the unit tests, the demos, the conformance ties (a *model's*
//! counterexample), the mutation sweep (our list of constraints), the per-column
//! probe (our perturbation). Only Quint and Kani search, and both search a small
//! box. So the discovery rate has been bounded by attention, which does not scale
//! and is not repeatable — and both fail-opens found this week were found by
//! running the thing against a real node, not by any check.
//!
//! These codecs are reached by bytes a counterparty chose. `Record::decode` is
//! handed 64 bytes off the Bitcoin chain, published by anyone;
//! `Issuance::decode` gets 76 the same way. That is the definition of an
//! attacker-controlled parser.
//!
//! ## The three properties, and why the second is the interesting one
//!
//! 1. **No panic, ever.** A panic in a consensus decoder reached from chain data
//!    is a remote crash of every wallet that scans.
//!
//! 2. **Canonicality: `decode` then `encode` must return the original bytes.**
//!    This is `[NO-BYTE-IDENTITY]`'s invariant, checked rather than argued. The
//!    register says the decoders "**reject** out-of-range limbs rather than
//!    reducing them, so encode∘decode is a bijection" — the whole reason the
//!    unmaintained encoder underneath is not load-bearing. If any input decodes
//!    to a value that re-encodes differently, **two distinct byte strings name
//!    one record**, and every consensus rule keyed on bytes has an alias. That is
//!    a double-spend shaped hole, and the argument for it being impossible is
//!    currently prose.
//!
//! 3. **Determinism.** Same bytes, same verdict.
//!
//! ## Why a seeded generator and not `cargo-fuzz`
//!
//! These inputs are **fixed-width byte arrays with no structure to discover** —
//! 32, 64 and 76 bytes, no length fields, no nesting, no state machine. Coverage
//! guidance earns its cost when it has to *find* the shape of an input; here
//! there is no shape to find, and the branches are a handful of range checks.
//! What matters instead is hitting the field-order boundary exactly, which is a
//! targeted generator's job and is done below.
//!
//! Deterministic, so a failure is reproducible from the printed seed rather than
//! being a story about a machine that once went red. Runs in about a second, so
//! it goes in CI rather than in a nightly nobody reads.

use uv_kernel2::digest::{decode as digest_decode, encode as digest_encode, DIGEST_BYTES};
use uv_kernel2::issuance::{Issuance, ISSUANCE_BYTES, TAG};
use uv_kernel2::record::{Record, RECORD_BYTES};

/// xorshift64*. Not cryptography — a reproducible stream of bytes.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// BabyBear's modulus. A 32-bit limb at or above this must be refused, and the
/// values immediately around it are where an off-by-one lives.
const P: u32 = 0x7800_0001;

/// Interesting u32 limb values: the boundary, its neighbours, and the extremes.
const EDGE: [u32; 10] = [
    0,
    1,
    2,
    P - 2,
    P - 1,
    P,
    P + 1,
    P.wrapping_add(2),
    u32::MAX - 1,
    u32::MAX,
];

/// Fill `out` with limbs drawn from [`EDGE`] — the inputs a uniform generator
/// would essentially never produce, and the only ones where the range check can
/// be wrong.
fn fill_edgy(rng: &mut Rng, out: &mut [u8]) {
    for limb in out.chunks_mut(4) {
        let v = EDGE[(rng.next_u64() % EDGE.len() as u64) as usize];
        let b = v.to_le_bytes();
        let n = limb.len();
        limb.copy_from_slice(&b[..n]);
    }
}

/// Limbs that are **mostly valid**, with a minority pulled to the boundary.
///
/// **The generator needs this and the first version did not have it.** Only
/// about 47% of uniform `u32` values fall below the field order, so a 16-limb
/// record built from uniform bytes decodes roughly five times in a million and a
/// 60,000-round run saw **zero**. The canonicality assertion — the property this
/// file exists for — never executed. The anti-vacuity check caught it, which is
/// the argument for having one: a fuzzer that cannot get past the first check
/// reports success and tests nothing.
///
/// So: draw each limb in range, then push a fraction of them to `P` and its
/// neighbours. That keeps the deep path reachable while still aiming at the only
/// boundary that matters.
fn fill_mostly_valid(rng: &mut Rng, out: &mut [u8]) {
    for limb in out.chunks_mut(4) {
        let r = rng.next_u64();
        let v = if r.is_multiple_of(8) {
            EDGE[(r >> 3) as usize % EDGE.len()]
        } else {
            (r >> 3) as u32 % P
        };
        let b = v.to_le_bytes();
        let n = limb.len();
        limb.copy_from_slice(&b[..n]);
    }
}

const ROUNDS: usize = 60_000;

// ---------------------------------------------------------------------------

/// 64 bytes off the chain, published by anyone.
#[test]
fn record_decode_survives_anything_and_is_canonical() {
    let mut rng = Rng(0x5EED_0001);
    let mut accepted = 0u64;

    for i in 0..ROUNDS {
        let mut bytes = [0u8; RECORD_BYTES];
        // Three generators: uniform bytes (shallow, catches panics), boundary
        // limbs (the range check), and mostly-valid limbs (the only ones that
        // reach the canonicality assertion at all).
        match i % 3 {
            0 => rng.fill(&mut bytes),
            1 => fill_edgy(&mut rng, &mut bytes),
            _ => fill_mostly_valid(&mut rng, &mut bytes),
        }

        let Some(rec) = Record::decode(&bytes) else {
            continue;
        };
        accepted += 1;

        assert_eq!(
            rec.encode(),
            bytes,
            "round {i}: a record decoded from bytes that are NOT its encoding. Two \
             distinct byte strings then name one record, and every consensus rule \
             keyed on bytes has an alias."
        );
        assert!(
            Record::decode(&bytes).is_some(),
            "round {i}: decoding is not deterministic"
        );
    }

    // Anti-vacuity: if nothing ever decoded, the assertions above never ran.
    assert!(
        accepted > 0,
        "no input decoded in {ROUNDS} rounds — the canonicality assertion never \
         executed and this test proves nothing"
    );
    println!("record: {ROUNDS} inputs, {accepted} accepted, all canonical");
}

/// 76 bytes off the chain, same exposure.
#[test]
fn issuance_decode_survives_anything_and_is_canonical() {
    let mut rng = Rng(0x5EED_0002);
    let mut accepted = 0u64;

    for i in 0..ROUNDS {
        let mut bytes = [0u8; ISSUANCE_BYTES];
        match i % 3 {
            0 => rng.fill(&mut bytes),
            1 => fill_edgy(&mut rng, &mut bytes),
            _ => fill_mostly_valid(&mut rng, &mut bytes),
        }
        // The 4-byte tag is checked before anything else, so without it almost
        // nothing reaches the limb decoding and the canonicality assertion never
        // runs. Set it on most inputs; leave it random on the rest so a decoder
        // that stopped checking the tag would still be caught.
        if i % 3 != 0 {
            bytes[..4].copy_from_slice(&TAG);
        }

        let Some(iss) = Issuance::decode(&bytes) else {
            continue;
        };
        accepted += 1;
        assert_eq!(
            iss.encode(),
            bytes,
            "round {i}: an issuance decoded from bytes that are not its encoding"
        );
    }
    assert!(
        accepted > 0,
        "no issuance decoded in {ROUNDS} rounds — the canonicality assertion never ran"
    );
    println!("issuance: {ROUNDS} inputs, {accepted} accepted, all canonical");
}

/// The digest codec both of the above are built from.
#[test]
fn digest_decode_survives_anything_and_is_canonical() {
    let mut rng = Rng(0x5EED_0003);
    let mut accepted = 0u64;

    for i in 0..ROUNDS {
        let mut bytes = [0u8; DIGEST_BYTES];
        match i % 3 {
            0 => rng.fill(&mut bytes),
            1 => fill_edgy(&mut rng, &mut bytes),
            _ => fill_mostly_valid(&mut rng, &mut bytes),
        }

        let Some(d) = digest_decode(&bytes) else {
            continue;
        };
        accepted += 1;
        assert_eq!(
            digest_encode(&d),
            bytes,
            "round {i}: a digest decoded from non-canonical bytes — a limb was \
             reduced rather than refused, so two byte strings name one digest"
        );
    }
    assert!(accepted > 0, "nothing decoded; the assertion never ran");
    println!("digest: {ROUNDS} inputs, {accepted} accepted, all canonical");
}

/// **The boundary, exhaustively, in the one place an off-by-one would live.**
///
/// Every limb value from `P - 4` to `P + 4` in every one of the eight positions.
/// A uniform generator reaches this region with probability about 2^-29 per
/// limb; a targeted one reaches it every time.
#[test]
fn the_field_order_boundary_is_exact_in_every_limb() {
    for pos in 0..DIGEST_BYTES / 4 {
        for delta in -4i64..=4 {
            let v = (P as i64 + delta) as u32;
            let mut bytes = [0u8; DIGEST_BYTES];
            bytes[pos * 4..pos * 4 + 4].copy_from_slice(&v.to_le_bytes());

            let decoded = digest_decode(&bytes);
            if v < P {
                assert!(
                    decoded.is_some(),
                    "limb {pos} = {v} is below the field order {P} and must be accepted"
                );
                assert_eq!(
                    digest_encode(&decoded.unwrap()),
                    bytes,
                    "limb {pos} = {v}: accepted but not canonical"
                );
            } else {
                assert!(
                    decoded.is_none(),
                    "limb {pos} = {v} is at or above the field order {P} and must be \
                     REFUSED, not reduced — reducing it makes {v} and {} name the \
                     same digest",
                    v.wrapping_sub(P)
                );
            }
        }
    }
}
