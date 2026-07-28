//! Canonical 32-byte encoding of a [`Digest`].
//!
//! Eight BabyBear elements, each as its canonical residue in 4 little-endian
//! bytes. Decoding **rejects** any limb ≥ p rather than reducing it: reduction
//! would give every digest 2–3 byte-level aliases, and anything keyed by digest
//! bytes — records on Bitcoin above all — must have exactly one encoding per
//! value. Encode∘decode and decode∘encode are both identities on their valid
//! domains, and the tests pin that.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use uv_air::wots::{Digest, N};

/// Serialized digest length in bytes.
pub const DIGEST_BYTES: usize = N * 4;

/// Canonical bytes of a digest.
pub fn encode(d: &Digest) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (i, e) in d.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&e.as_canonical_u32().to_le_bytes());
    }
    out
}

/// Parse canonical bytes. `None` if any limb is ≥ p — a non-canonical
/// encoding, which consensus must treat as malformed, never as its reduction.
pub fn decode(bytes: &[u8; DIGEST_BYTES]) -> Option<Digest> {
    let mut out = [BabyBear::ZERO; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        let v = u32::from_le_bytes(b);
        if v >= BabyBear::ORDER_U32 {
            return None;
        }
        *slot = BabyBear::from_u32(v);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let d: Digest = core::array::from_fn(|i| BabyBear::from_u32(1000 + i as u32));
        assert_eq!(decode(&encode(&d)), Some(d));
    }

    #[test]
    fn non_canonical_bytes_are_rejected_not_reduced() {
        let mut bytes = encode(&[BabyBear::ZERO; N]);
        // p itself: reduces to 0, and MUST NOT be accepted as an alias of 0.
        bytes[..4].copy_from_slice(&BabyBear::ORDER_U32.to_le_bytes());
        assert_eq!(decode(&bytes), None);
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&bytes), None);
    }

    #[test]
    fn the_edge_of_the_field_is_canonical() {
        let d = [BabyBear::from_u32(BabyBear::ORDER_U32 - 1); N];
        assert_eq!(decode(&encode(&d)), Some(d));
    }
}

#[cfg(test)]
mod canonicality {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeField32;

    /// We depend on upstream rejecting out-of-range field elements rather than
    /// reducing them, and nothing here asserted it.
    ///
    /// If `serde` for `BabyBear` ever *reduced* instead, every field element on
    /// the wire would gain two byte-level representations. That is not
    /// exploitable today — serialized bytes are never an identity in this
    /// system — but it is a landmine for anything that later hashes an
    /// encoding, which the accumulator design (spec/99 `[ACC]`) would. A minor
    /// dependency bump could change it silently; this fails loudly instead.
    #[test]
    fn field_elements_out_of_range_are_rejected_not_reduced() {
        let p = BabyBear::ORDER_U32;
        for bad in [p, p + 1, u32::MAX] {
            let bytes = bincode::serialize(&bad).expect("u32 serializes");
            assert!(
                bincode::deserialize::<BabyBear>(&bytes).is_err(),
                "{bad} >= p was accepted; upstream now reduces instead of rejecting, \
                 which gives every field element an alias on the wire"
            );
        }
        // ...and the largest valid element still round-trips.
        let ok = bincode::serialize(&(p - 1)).expect("u32 serializes");
        assert!(bincode::deserialize::<BabyBear>(&ok).is_ok());
    }
}
