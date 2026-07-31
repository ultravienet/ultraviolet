//! Attacker-chosen bytes into `open`. The carrier is untrusted by construction,
//! so this is the one parser reached by bytes the *delivery path* chose.
//!
//! `formal/delivery.qnt` proves a hostile carrier costs time and privacy, never
//! funds — but that model is about *verdicts*, and it assumes `open` returns
//! one. A panic is not a verdict. `open` is called on whatever arrives in a chat
//! attachment, and a wallet that crashes on a malformed one is a wallet a
//! carrier can stop, which is the liveness half of `[DOS-ORDER]` reached by a
//! path nothing had tested.
//!
//! Unlike the fixed-width consensus codecs, `Sealed` has **four independently
//! attacker-chosen variable-length fields**, so the lengths themselves are the
//! interesting input: a slice that is not 32 bytes, an empty ciphertext, a
//! ciphertext shorter than its authentication tag, absurd lengths, and every
//! combination.
//!
//! **The property is uniform and deliberately weak: `open` must always return.**
//! `Ok` or `Err`, never a panic and never a hang. Anything stronger would be a
//! claim about the cryptography, which is assumed (`formal/COMPOSITION.md` A6).
//!
//! There is a second property worth stating because the code goes out of its way
//! to hold it: **`NotForMe` and `Malformed` must not become a distinguisher for
//! attacker-controlled length**. `open`'s own doc says an authenticated cipher
//! cannot distinguish "not addressed to me" from "altered in flight" and a
//! receiver doing trial-decapsulation must not learn which. That is checked at
//! the end.

use uv_envelope::{derive_scan, open, seal, Sealed};

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
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
    /// A length an attacker would actually try.
    fn awkward_len(&mut self) -> usize {
        const LENS: [usize; 12] = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 1088, 1089];
        LENS[(self.next_u64() % LENS.len() as u64) as usize]
    }
}

/// Every field independently garbage, including its length.
#[test]
fn open_always_returns_on_arbitrary_sealed_values() {
    let (secret, _public) = derive_scan(&[3u8; 32]);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    for _ in 0..4_000 {
        let (a, b, c, d) = (
            rng.awkward_len(),
            rng.awkward_len(),
            rng.awkward_len(),
            rng.awkward_len(),
        );
        let sealed = Sealed {
            ml_kem_ct: rng.bytes(a),
            x25519_eph: rng.bytes(b),
            nonce: rng.bytes(c),
            ct: rng.bytes(d),
        };
        // The property: it returns. A panic here fails the test by unwinding.
        let _ = open(&secret, &sealed);
    }
}

/// **The realistic attack: tamper with a genuine sealed message.**
///
/// Uniform garbage almost never reaches past the first length check. A carrier
/// holds a *real* envelope and can flip any byte of it, which reaches the
/// decapsulation and the AEAD — the code that actually does work.
#[test]
fn open_always_returns_on_a_tampered_real_envelope() {
    let (secret, public) = derive_scan(&[5u8; 32]);
    let genuine = seal(&public, b"a payment bundle, more or less").expect("seal");
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);

    let mut opened_ok = 0u64;
    for _ in 0..4_000 {
        let mut s = Sealed {
            ml_kem_ct: genuine.ml_kem_ct.clone(),
            x25519_eph: genuine.x25519_eph.clone(),
            nonce: genuine.nonce.clone(),
            ct: genuine.ct.clone(),
        };
        // Flip one byte of one field.
        match rng.next_u64() % 4 {
            0 if !s.ml_kem_ct.is_empty() => {
                let i = (rng.next_u64() as usize) % s.ml_kem_ct.len();
                s.ml_kem_ct[i] ^= 1 << (rng.next_u64() % 8);
            }
            1 if !s.x25519_eph.is_empty() => {
                let i = (rng.next_u64() as usize) % s.x25519_eph.len();
                s.x25519_eph[i] ^= 1 << (rng.next_u64() % 8);
            }
            2 if !s.nonce.is_empty() => {
                let i = (rng.next_u64() as usize) % s.nonce.len();
                s.nonce[i] ^= 1 << (rng.next_u64() % 8);
            }
            _ if !s.ct.is_empty() => {
                let i = (rng.next_u64() as usize) % s.ct.len();
                s.ct[i] ^= 1 << (rng.next_u64() % 8);
            }
            _ => {}
        }
        if open(&secret, &s).is_ok() {
            opened_ok += 1;
        }
    }

    assert_eq!(
        opened_ok, 0,
        "{opened_ok} single-bit tampers still opened. The seal is authenticated; a \
         modified envelope must never decrypt, or the carrier can alter payments \
         in flight"
    );
}

/// Truncation at every length, which is what a partial write or a lying carrier
/// produces.
#[test]
fn open_always_returns_on_truncation_at_every_length() {
    let (secret, public) = derive_scan(&[9u8; 32]);
    let genuine = seal(&public, b"truncate me").expect("seal");

    for n in 0..genuine.ct.len() {
        let s = Sealed {
            ml_kem_ct: genuine.ml_kem_ct.clone(),
            x25519_eph: genuine.x25519_eph.clone(),
            nonce: genuine.nonce.clone(),
            ct: genuine.ct[..n].to_vec(),
        };
        assert!(
            open(&secret, &s).is_err(),
            "a ciphertext truncated to {n} bytes must not open"
        );
    }
    for n in 0..genuine.ml_kem_ct.len().min(64) {
        let s = Sealed {
            ml_kem_ct: genuine.ml_kem_ct[..n].to_vec(),
            x25519_eph: genuine.x25519_eph.clone(),
            nonce: genuine.nonce.clone(),
            ct: genuine.ct.clone(),
        };
        assert!(
            open(&secret, &s).is_err(),
            "a KEM ciphertext truncated to {n} bytes must not open"
        );
    }
}

/// The genuine envelope still opens, so the refusals above are not universal.
#[test]
fn a_genuine_envelope_still_opens() {
    let (secret, public) = derive_scan(&[11u8; 32]);
    let msg = b"the control case";
    let sealed = seal(&public, msg).expect("seal");
    assert_eq!(
        open(&secret, &sealed).expect("a genuine envelope must open"),
        msg,
        "if this fails, every refusal above is refusing everything and proves nothing"
    );
}
