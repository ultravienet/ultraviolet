//! Claim P3: **the carrier sees only opaque ciphertext.**
//!
//! Signal, the relay, a directory, a chat attachment sitting on someone's phone
//! — every one of them handles the bundle and none of them is trusted with it.
//! P3 is what makes that acceptable, and until 2026-07-30 its only evidence was
//! `demo/check_sealed.py`, a demo-time script. A demo is not a gate: it runs on
//! one bundle produced by one run, and nothing fails if somebody adds a field to
//! the envelope in the clear.
//!
//! So this is that check, in CI, over the *envelope API* rather than over one
//! file a demo happened to write — and it looks for the payload's own secret
//! bytes rather than for field names, because the wire format is raw bytes and
//! has no field names left to find.
//!
//! ## What P3 does and does not claim
//!
//! **Bytes are opaque.** Nothing recoverable from the payload appears on the
//! wire, and the same payload sealed twice produces different bytes, so a carrier
//! cannot recognise a repeated payment by its ciphertext.
//!
//! **Length is not hidden, and this test asserts what leaks rather than pretending
//! it does not.** The wire is a fixed overhead plus the payload, so a carrier
//! learns the payload's size to within a constant. That is real metadata: bundle
//! size grows with lineage length, so a carrier can estimate how many hands a coin
//! has passed through. It is stated in `SPEC.md` §10 and it is the honest limit of
//! this claim, not a defect this test is hiding.
//!
//! **This says nothing about the cryptography.** ML-KEM-768 and X25519 and
//! ChaCha20-Poly1305 being secure is an assumption, and off the money path by
//! construction — a break here costs privacy, never funds.

use uv_envelope::{derive_scan, open, seal, ScanPublic, ScanSecret};

/// A payload with markers that would be unmistakable in the clear.
fn payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(b"UV-PAYEE-SLOT-0007");
    p.extend_from_slice(&700u64.to_le_bytes());
    p.extend_from_slice(b"asset=deadbeefcafef00d");
    // Something long and high-entropy, standing in for the proof bytes that
    // dominate a real bundle.
    p.extend((0u8..=255).cycle().take(2048).map(|b| b ^ 0x5A));
    p.extend_from_slice(b"UV-END-OF-LINEAGE");
    p
}

/// A payee's scan keypair, derived from a wallet seed the way a real one is —
/// `derive_scan` is the only constructor, because a scan key that is not derived
/// from the seed is a scan key a restored wallet cannot rebuild.
fn keys() -> (ScanSecret, ScanPublic) {
    derive_scan(&[0x2Au8; 32])
}

/// The wire carries none of the payload's recognisable bytes — and the round
/// trip still works, so this is not passing because the seal is broken.
#[test]
fn no_payload_bytes_appear_on_the_wire() {
    let (secret, public) = keys();
    let plain = payload();
    let sealed = seal(&public, &plain).expect("seal");

    // The whole wire, exactly as a carrier would hold it.
    let mut wire = Vec::new();
    wire.extend_from_slice(&sealed.ml_kem_ct);
    wire.extend_from_slice(&sealed.x25519_eph);
    wire.extend_from_slice(&sealed.nonce);
    wire.extend_from_slice(&sealed.ct);

    // The control first: an unopenable envelope would trivially leak nothing.
    assert_eq!(
        open(&secret, &sealed).expect("open"),
        plain,
        "control: the payee must be able to read it, or leaking nothing is meaningless"
    );

    let markers: [&[u8]; 4] = [
        b"UV-PAYEE-SLOT-0007",
        b"asset=deadbeefcafef00d",
        b"UV-END-OF-LINEAGE",
        &700u64.to_le_bytes(),
    ];
    for m in markers {
        assert!(
            !contains(&wire, m),
            "a plaintext marker ({:?}) appears in a supposedly sealed bundle",
            String::from_utf8_lossy(m)
        );
    }

    // And no long run of the payload survives anywhere. The markers above are
    // what a reader would look for; this is what a *grep* would find — any
    // 32-byte window of the plaintext appearing verbatim on the wire.
    let mut leaked_windows = 0usize;
    for w in plain.windows(32) {
        if contains(&wire, w) {
            leaked_windows += 1;
        }
    }
    assert_eq!(
        leaked_windows, 0,
        "{leaked_windows} thirty-two-byte windows of the payload appear verbatim \
         on the wire"
    );
}

/// The same payment sealed twice is two different byte strings, so a carrier
/// cannot fingerprint a repeated bundle — which matters because a re-send after
/// a dropped message is an ordinary event (`formal/delivery.qnt`).
#[test]
fn sealing_the_same_payload_twice_gives_different_bytes() {
    let (secret, public) = keys();
    let plain = payload();
    let a = seal(&public, &plain).expect("seal a");
    let b = seal(&public, &plain).expect("seal b");

    assert_ne!(
        a.ct, b.ct,
        "identical ciphertext would fingerprint the payment"
    );
    assert_ne!(
        a.nonce, b.nonce,
        "a repeated nonce is a broken cipher, not a leak"
    );
    assert_ne!(
        a.ml_kem_ct, b.ml_kem_ct,
        "encapsulation must be fresh per seal"
    );
    assert_ne!(
        a.x25519_eph, b.x25519_eph,
        "the ephemeral key must be ephemeral"
    );

    // Both still open to the same plaintext.
    assert_eq!(open(&secret, &a).expect("open a"), plain);
    assert_eq!(open(&secret, &b).expect("open b"), plain);
}

/// What the carrier *does* learn, asserted so it stays a stated limit rather
/// than becoming a surprise. If envelope overhead changes, this test says so.
#[test]
fn the_carrier_learns_the_size_and_nothing_else_structural() {
    let (_secret, public) = keys();
    let small = seal(&public, &[0u8; 64]).expect("seal small");
    let large = seal(&public, &[0u8; 4096]).expect("seal large");

    let len = |s: &uv_envelope::Sealed| {
        s.ml_kem_ct.len() + s.x25519_eph.len() + s.nonce.len() + s.ct.len()
    };

    // Fixed parts are fixed; only the body grows. This is the leak, quantified.
    assert_eq!(
        small.ml_kem_ct.len(),
        large.ml_kem_ct.len(),
        "encapsulation size must not depend on the payload"
    );
    assert_eq!(small.nonce.len(), large.nonce.len());
    assert_eq!(small.x25519_eph.len(), large.x25519_eph.len());
    let overhead = len(&small) - 64;
    assert_eq!(
        len(&large) - 4096,
        overhead,
        "envelope overhead must be constant, so wire size reveals payload size \
         and nothing more; a payload-dependent overhead would leak more than length"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}
