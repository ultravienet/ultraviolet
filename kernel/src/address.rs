//! PQ-signed address records (spec/02-NOTES.md, spec/05-NETWORK.md).
//!
//! Payment addressing rides Nostr as events, but authority never rests on the
//! classical npub: each record is cross-signed with SLH-DSA and chained to a
//! PQ root, so wallets verify the PQ chain and treat Nostr purely as the
//! bulletin board. A quantum-forged npub can deface a profile; it cannot
//! redirect a payment.

use crate::hash::{boundary_hash, Hash256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const ADDRESS_DOMAIN: &str = "uv/address-record/v1";

/// An address record: what a sender needs to pay someone, PQ-authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AddressRecord {
    /// ML-KEM(+X25519 hybrid) encapsulation key for note encryption / scanning.
    pub scan_kem_pk: Vec<u8>,
    /// Root committing to the owner's spend keys (spec/02-NOTES.md).
    pub spend_root: Hash256,
    /// Hash of the previous record in this identity's chain
    /// (all-zero for the root record).
    pub prev: Hash256,
    /// SLH-DSA signature over [`Self::signing_payload`] by the identity's PQ
    /// root key (or a key it has chained to). Verification lives behind the
    /// `slh` feature via [`crate::sig`].
    pub pq_sig: Vec<u8>,
}

impl AddressRecord {
    /// The exact bytes the SLH-DSA signature must cover.
    pub fn signing_payload(&self) -> Hash256 {
        boundary_hash(
            ADDRESS_DOMAIN,
            &[&self.scan_kem_pk, &self.spend_root, &self.prev],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_binds_every_field() {
        let base = AddressRecord {
            scan_kem_pk: vec![1, 2, 3],
            spend_root: [4; 32],
            prev: [0; 32],
            pq_sig: vec![],
        };
        let mut other = base.clone();
        other.spend_root = [5; 32];
        assert_ne!(base.signing_payload(), other.signing_payload());
        let mut chained = base.clone();
        chained.prev = [9; 32];
        assert_ne!(base.signing_payload(), chained.signing_payload());
    }
}
