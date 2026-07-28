//! WOTS+ one-time signatures over Poseidon2 — the host-side reference.
//!
//! ## Why this replaces SLH-DSA on the money path
//!
//! Measured: verifying SLH-DSA in-circuit is **4.0M of a payment's 5.18M cycles**
//! (77%), and almost all of that hypertree exists to make a key *reusable*.
//! Ultraviolet doesn't need reusability for note spends — a note is spent exactly
//! once and the nullifier enforces it — so a one-time signature suffices.
//!
//! Poseidon2 rather than SHA-256 because Poseidon2 is the proof system's own
//! hash: 402 cycles per in-circuit call against SHA-256's 1,353, and in a
//! hand-written AIR one permutation is a single row.
//!
//! ## Why WOTS+ and not a bare hash preimage
//!
//! A circuit could simply prove knowledge of `x` with `H(x) = owner_key` — one
//! hash instead of a thousand. That was the tempting design, and the fact that
//! **SP1's raw STARK is not zero-knowledge** kills it: a bare preimage sitting in
//! an unblinded witness is a bearer secret, and one leak makes the note spendable
//! by anyone. A WOTS+ signature is *payload-bound* — it authorizes this exact
//! transition and nothing else, so it stays safe even if fragments escape.
//! Paying ~1,000 hashes for leak-tolerance is the right trade.
//!
//! ## The one-time rule, which is not optional
//!
//! Signing two different messages with one key violates WOTS+'s one-time
//! security assumption. Each signature exposes one value from every hash chain;
//! combining distinct exposures can enable forgery, although it does not in
//! general reveal the entire private key. Hence `owner_key` must be **per note**
//! (spec/99), and the never-re-sign discipline is protocol-wide.
//!
//! ## Parameters
//!
//! Classic WOTS+ at `w = 16` over a 32-byte digest: 64 message digits, 3
//! checksum digits, 67 chains of ≤15 steps. That is ~1,005 chain permutations
//! plus 66 compressions — which is why the AIR was benchmarked at ~1,024 rows.
//!
//! A note on `w`: total hashing is roughly `chains × (w-1)`, so *smaller* `w` is
//! cheaper in circuit (w=4 gives ~512 permutations) at the cost of a larger
//! signature. `LOG_W` is a constant here so that tradeoff can be measured rather
//! than argued.

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

/// Poseidon2 state width. A chain value occupies the first [`N`] elements.
pub const WIDTH: usize = 16;
/// Digest size in field elements. 8 × ~31 bits ≈ 248 bits.
pub const N: usize = 8;
/// Winternitz parameter exponent: `w = 2^LOG_W`.
pub const LOG_W: usize = 4;
/// Winternitz parameter.
pub const W: usize = 1 << LOG_W;
/// Message digits: a digest is 32 bytes, and `LOG_W = 4` means one digit per nibble.
pub const MSG_DIGITS: usize = (N * 4 * 8) / LOG_W;
/// Checksum digits: the checksum is at most `MSG_DIGITS * (W-1)`, so it needs
/// `ceil(log_w(that))` digits — 3 for the classic parameters.
pub const CKSUM_DIGITS: usize = 3;
/// One chain per digit.
pub const CHAINS: usize = MSG_DIGITS + CKSUM_DIGITS;

/// A chain value: [`N`] field elements.
pub type Digest = [BabyBear; N];

/// A WOTS+ signature: one chain value per digit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub [Digest; CHAINS]);

/// Build the permutation with **published, fixed** round constants.
///
/// Deliberately not `from_rng`: host and circuit must agree on constants, and a
/// protocol cannot have per-instance ones.
pub fn permutation() -> Poseidon2BabyBear<WIDTH> {
    default_babybear_poseidon2_16()
}

fn zero_digest() -> Digest {
    [BabyBear::ZERO; N]
}

/// One chain step: pad the value into a width-16 state, permute, keep the rate.
///
/// One permutation per step is what makes this cheap in-circuit — a single AIR
/// row per step, with no lookups needed (see [`crate::wots`] module docs).
pub fn step(perm: &Poseidon2BabyBear<WIDTH>, x: &Digest) -> Digest {
    let mut state = [BabyBear::ZERO; WIDTH];
    state[..N].copy_from_slice(x);
    perm.permute_mut(&mut state);
    let mut out = zero_digest();
    out.copy_from_slice(&state[..N]);
    out
}

/// Iterate [`step`] `times` times.
pub fn chain(perm: &Poseidon2BabyBear<WIDTH>, x: &Digest, times: usize) -> Digest {
    let mut v = *x;
    for _ in 0..times {
        v = step(perm, &v);
    }
    v
}

/// Compress the per-chain tips into one public key by absorbing them.
///
/// A sponge rather than a Merkle tree: both cost ~one permutation per chain, and
/// the sponge needs no tree bookkeeping in the AIR.
pub fn compress(perm: &Poseidon2BabyBear<WIDTH>, tips: &[Digest; CHAINS]) -> Digest {
    let mut state = [BabyBear::ZERO; WIDTH];
    for tip in tips.iter() {
        for i in 0..N {
            state[i] += tip[i];
        }
        perm.permute_mut(&mut state);
    }
    let mut out = zero_digest();
    out.copy_from_slice(&state[..N]);
    out
}

/// Base-`w` digits of a digest, plus the checksum digits.
///
/// Digits come from the little-endian canonical byte encoding, so each is in
/// `0..W` by construction — which is what lets the AIR range-check them with
/// boolean bit columns instead of a lookup table. Some byte patterns are
/// unreachable because field elements are `< p`; that shrinks the message space
/// slightly and is harmless, since the message is itself a hash.
pub fn digits(msg: &Digest) -> [u8; CHAINS] {
    let mut out = [0u8; CHAINS];
    let mut bytes = [0u8; N * 4];
    for (i, e) in msg.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&e.as_canonical_u32().to_le_bytes());
    }
    debug_assert_eq!(LOG_W, 4, "digit extraction below assumes nibbles");
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = b & 0x0f;
        out[i * 2 + 1] = b >> 4;
    }

    // Checksum over the *complements*, so raising any message digit lowers the
    // checksum. Without it a forger could walk a chain forward and claim a
    // larger digit.
    let mut cksum: u32 = out[..MSG_DIGITS]
        .iter()
        .map(|d| (W - 1 - *d as usize) as u32)
        .sum();
    for i in 0..CKSUM_DIGITS {
        out[MSG_DIGITS + i] = (cksum & (W as u32 - 1)) as u8;
        cksum >>= LOG_W;
    }
    debug_assert_eq!(cksum, 0, "checksum must fit in CKSUM_DIGITS");
    out
}

/// Per-chain secret starts, derived from one seed so only the seed is stored.
pub fn secret_starts(perm: &Poseidon2BabyBear<WIDTH>, seed: &[u8; 32]) -> [Digest; CHAINS] {
    let mut starts = [zero_digest(); CHAINS];
    for (i, s) in starts.iter_mut().enumerate() {
        // Domain-separate by chain index so chains are independent.
        let mut state = [BabyBear::ZERO; WIDTH];
        for (j, chunk) in seed.chunks(4).enumerate() {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            state[j] = BabyBear::from_u32(u32::from_le_bytes(b) % BabyBear::ORDER_U32);
        }
        state[N] = BabyBear::from_u32(i as u32);
        state[N + 1] = BabyBear::from_u32(0x_5707_5721);
        perm.permute_mut(&mut state);
        s.copy_from_slice(&state[..N]);
    }
    starts
}

/// The public key: every chain walked to the end, then compressed.
pub fn public_key(perm: &Poseidon2BabyBear<WIDTH>, seed: &[u8; 32]) -> Digest {
    let starts = secret_starts(perm, seed);
    let mut tips = [zero_digest(); CHAINS];
    for i in 0..CHAINS {
        tips[i] = chain(perm, &starts[i], W - 1);
    }
    compress(perm, &tips)
}

/// Sign: walk each chain `d_i` steps and reveal where you stopped.
///
/// **Signing twice with the same seed reveals the secret key.** Callers must
/// enforce one-time use; the protocol does so with per-note keys.
pub fn sign(perm: &Poseidon2BabyBear<WIDTH>, seed: &[u8; 32], msg: &Digest) -> Signature {
    let starts = secret_starts(perm, seed);
    let d = digits(msg);
    let mut sig = [zero_digest(); CHAINS];
    for i in 0..CHAINS {
        sig[i] = chain(perm, &starts[i], d[i] as usize);
    }
    Signature(sig)
}

/// Verify: walk each revealed value the *remaining* `w-1-d_i` steps, compress,
/// and compare against the public key.
///
/// This is exactly what the AIR constrains, which is why it is written as a
/// per-chain loop of uniform steps.
pub fn verify(perm: &Poseidon2BabyBear<WIDTH>, pk: &Digest, msg: &Digest, sig: &Signature) -> bool {
    let d = digits(msg);
    let mut tips = [zero_digest(); CHAINS];
    for i in 0..CHAINS {
        tips[i] = chain(perm, &sig.0[i], W - 1 - d[i] as usize);
    }
    compress(perm, &tips) == *pk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_from(tag: u32) -> Digest {
        let perm = permutation();
        let mut state = [BabyBear::ZERO; WIDTH];
        state[0] = BabyBear::from_u32(tag);
        perm.permute_mut(&mut state);
        let mut d = zero_digest();
        d.copy_from_slice(&state[..N]);
        d
    }

    #[test]
    fn parameters_are_the_classic_ones() {
        assert_eq!(W, 16);
        assert_eq!(MSG_DIGITS, 64);
        assert_eq!(CHAINS, 67);
        // ~1,005 chain steps + 67 compressions: the workload the AIR was sized for.
        assert_eq!(CHAINS * (W - 1), 1005);
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let perm = permutation();
        let seed = [3u8; 32];
        let pk = public_key(&perm, &seed);
        let msg = msg_from(1);
        let sig = sign(&perm, &seed, &msg);
        assert!(verify(&perm, &pk, &msg, &sig));
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let perm = permutation();
        let seed = [4u8; 32];
        let pk = public_key(&perm, &seed);
        let sig = sign(&perm, &seed, &msg_from(1));
        assert!(
            !verify(&perm, &pk, &msg_from(2), &sig),
            "a signature must not transfer to another message"
        );
    }

    #[test]
    fn another_keys_signature_does_not_verify() {
        let perm = permutation();
        let pk = public_key(&perm, &[5u8; 32]);
        let msg = msg_from(7);
        let sig = sign(&perm, &[6u8; 32], &msg);
        assert!(!verify(&perm, &pk, &msg, &sig));
    }

    #[test]
    fn tampering_with_any_chain_is_caught() {
        let perm = permutation();
        let seed = [8u8; 32];
        let pk = public_key(&perm, &seed);
        let msg = msg_from(9);
        for i in [0usize, 33, CHAINS - 1] {
            let mut sig = sign(&perm, &seed, &msg);
            sig.0[i][0] += BabyBear::ONE;
            assert!(!verify(&perm, &pk, &msg, &sig), "chain {i} went unchecked");
        }
    }

    /// The checksum is what stops a forger walking a chain *forward* to claim a
    /// larger digit: doing so lowers the checksum, whose own chains would then
    /// have to be walked backwards, which requires inverting the hash.
    #[test]
    fn walking_a_chain_forward_breaks_the_checksum() {
        let perm = permutation();
        let seed = [11u8; 32];
        let pk = public_key(&perm, &seed);
        let msg = msg_from(12);
        let d = digits(&msg);
        let i = d[..MSG_DIGITS]
            .iter()
            .position(|&x| (x as usize) < W - 1)
            .expect("some digit is advanceable");

        let mut forged = sign(&perm, &seed, &msg);
        forged.0[i] = step(&perm, &forged.0[i]); // claim digit i is one larger
        assert!(
            !verify(&perm, &pk, &msg, &forged),
            "advancing a chain must not verify against the same message"
        );
    }

    /// The digit decomposition is canonical and injective.
    ///
    /// The AIR never decomposes the message; the *verifier* computes these
    /// digits and supplies them as public values. That is only sound if
    /// `digits()` is injective — two digests must never share a digit vector —
    /// which holds because `as_canonical_u32` is a bijection onto `0..p` and
    /// the nibble decomposition of a u32 is bijective. This test pins the
    /// composed round-trip: reconstructing each limb's u32 from its 8 nibbles
    /// recovers `as_canonical_u32` exactly, including at the field's edges
    /// (0 and p-1 = 0x78000000, the value where a p-shifted alias would first
    /// diverge if one could exist).
    #[test]
    fn digit_decomposition_is_canonical_and_injective() {
        use p3_field::PrimeField32;
        for v in [
            0u32,
            1,
            14,
            0x0F0F_0F0F,
            BabyBear::ORDER_U32 - 2,
            BabyBear::ORDER_U32 - 1,
        ] {
            let msg = [BabyBear::from_u32(v); N];
            let d = digits(&msg);
            for limb in 0..N {
                let rebuilt: u32 = (0..8).map(|k| u32::from(d[limb * 8 + k]) << (4 * k)).sum();
                assert_eq!(
                    rebuilt,
                    msg[limb].as_canonical_u32(),
                    "digits must decompose the canonical residue of {v}"
                );
            }
        }
        // And therefore distinct digests get distinct digit vectors.
        assert_ne!(
            digits(&[BabyBear::from_u32(5); N]),
            digits(&[BabyBear::from_u32(6); N])
        );
    }

    /// Signing is deterministic: one key and one message yield one signature,
    /// byte for byte, with no randomness anywhere in the construction.
    ///
    /// `formal/onetime.qnt` depends on this. Its `replay` module is the only
    /// discipline that is both safe and live, and it works by re-signing the
    /// *identical* payload when a signed-but-unsettled transfer must be
    /// rebroadcast — which reveals nothing only because it reproduces the one
    /// signature that already exists. If signing ever became randomized (a
    /// blinded or hedged variant, say), that recovery path could emit a second
    /// distinct signature and leave the scheme's one-time security regime, so
    /// this test guards the model's assumption.
    #[test]
    fn signing_is_deterministic() {
        let perm = permutation();
        let seed = [77u8; 32];
        for tag in [0u32, 3, 4242] {
            let msg = msg_from(tag);
            assert_eq!(
                sign(&perm, &seed, &msg).0,
                sign(&perm, &seed, &msg).0,
                "re-signing the same message must reproduce the same signature"
            );
        }
        // Different messages must of course differ, or the property above would
        // be satisfied trivially by a constant.
        assert_ne!(
            sign(&perm, &seed, &msg_from(3)).0,
            sign(&perm, &seed, &msg_from(4)).0
        );
    }

    #[test]
    fn digits_are_in_range_and_checksum_is_consistent() {
        for tag in [0u32, 1, 999, 12345] {
            let d = digits(&msg_from(tag));
            assert!(d.iter().all(|x| (*x as usize) < W), "digit out of range");
            let expect: u32 = d[..MSG_DIGITS]
                .iter()
                .map(|x| (W - 1 - *x as usize) as u32)
                .sum();
            let got = d[MSG_DIGITS..]
                .iter()
                .enumerate()
                .map(|(i, x)| (*x as u32) << (LOG_W * i))
                .sum::<u32>();
            assert_eq!(expect, got, "checksum digits must encode the checksum");
        }
    }
}
