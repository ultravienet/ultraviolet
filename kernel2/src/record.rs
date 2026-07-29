//! The 64-byte record: `nf ‖ H(bundle)`, unchanged from v1.
//!
//! What lands in the Bitcoin OP_RETURN. First occurrence of a nullifier wins
//! and binds that nullifier to one bundle hash forever — the rule every model
//! in `formal/` is built on, which is why this format survives the rewrite
//! byte-for-byte in *shape*: 32 bytes of nullifier, 32 of bundle hash. The
//! contents are now BabyBear digests in canonical encoding
//! ([`crate::digest`]), and parsing rejects non-canonical limbs — a record
//! that cannot round-trip is malformed, not "close enough".

use serde::{Deserialize, Serialize};
use uv_air::wots::Digest;

use crate::digest::{decode, encode, DIGEST_BYTES};

/// Serialized record length.
pub const RECORD_BYTES: usize = 2 * DIGEST_BYTES;

/// One record: the first occurrence of `nullifier` binds it to `bundle_hash`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub nullifier: Digest,
    pub bundle_hash: Digest,
}

impl Record {
    /// The 64 bytes that go on chain.
    pub fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut out = [0u8; RECORD_BYTES];
        out[..DIGEST_BYTES].copy_from_slice(&encode(&self.nullifier));
        out[DIGEST_BYTES..].copy_from_slice(&encode(&self.bundle_hash));
        out
    }

    /// Parse 64 bytes. `None` if either digest is non-canonical.
    pub fn decode(bytes: &[u8; RECORD_BYTES]) -> Option<Record> {
        let mut nf = [0u8; DIGEST_BYTES];
        nf.copy_from_slice(&bytes[..DIGEST_BYTES]);
        let mut bh = [0u8; DIGEST_BYTES];
        bh.copy_from_slice(&bytes[DIGEST_BYTES..]);
        Some(Record {
            nullifier: decode(&nf)?,
            bundle_hash: decode(&bh)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};

    #[test]
    fn round_trips_at_64_bytes() {
        let r = Record {
            nullifier: [BabyBear::from_u32(11); 8],
            bundle_hash: [BabyBear::from_u32(22); 8],
        };
        let bytes = r.encode();
        assert_eq!(bytes.len(), 64);
        assert_eq!(Record::decode(&bytes), Some(r));
    }

    #[test]
    fn a_non_canonical_record_is_malformed() {
        let r = Record {
            nullifier: [BabyBear::ZERO; 8],
            bundle_hash: [BabyBear::ZERO; 8],
        };
        let mut bytes = r.encode();
        bytes[..4].copy_from_slice(&BabyBear::ORDER_U32.to_le_bytes());
        assert_eq!(Record::decode(&bytes), None);
    }
}
