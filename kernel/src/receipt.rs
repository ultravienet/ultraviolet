//! Finality receipts and fraud proofs — SPEED LAYER, OPTIONAL
//! (spec/11-SPEED-LAYER.md; not referenced by the core protocol).
//!
//! A notary signs a reservation: "nf is reserved for this bundle hash in
//! this epoch; I will never sign a conflict." Two receipts from the same
//! notary for the same nullifier with different bundle hashes are a
//! self-contained fraud proof — two signatures anyone can verify, gossiped
//! over Nostr for free, and spendable against the notary's bond. These types
//! are kept tested and shelved until the stranger-retail market demands
//! sub-second guarantees.

use crate::hash::{boundary_hash, Hash256};
use crate::nullifier::Nullifier;

const RECEIPT_DOMAIN: &str = "uv/receipt/v1";

/// A signed finality reservation from a notary relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub nf: Nullifier,
    pub bundle_hash: Hash256,
    pub epoch: u64,
    /// Identifier (key hash) of the signing relay.
    pub relay_key: Hash256,
    /// The relay's signature over [`Self::signing_payload`].
    pub relay_sig: Vec<u8>,
}

impl Receipt {
    /// The exact bytes the relay signature must cover.
    pub fn signing_payload(&self) -> Hash256 {
        boundary_hash(
            RECEIPT_DOMAIN,
            &[
                &self.nf.0,
                &self.bundle_hash,
                &self.epoch.to_le_bytes(),
                &self.relay_key,
            ],
        )
    }
}

/// Proof that a relay equivocated: same relay, same nullifier, different
/// bundle hashes. Self-contained — verifying the two signatures convicts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FraudProof {
    pub a: Receipt,
    pub b: Receipt,
}

/// Detect equivocation between two receipts.
///
/// Returns a [`FraudProof`] iff both receipts come from the same relay and
/// reserve the same nullifier for different bundles. (Signature validity is
/// checked by the caller via [`crate::sig`]; a proof built from invalid
/// signatures convicts no one.)
pub fn detect_conflict(a: &Receipt, b: &Receipt) -> Option<FraudProof> {
    if a.relay_key == b.relay_key && a.nf == b.nf && a.bundle_hash != b.bundle_hash {
        Some(FraudProof { a: a.clone(), b: b.clone() })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(nf: u8, bundle: u8, relay: u8) -> Receipt {
        Receipt {
            nf: Nullifier([nf; 32]),
            bundle_hash: [bundle; 32],
            epoch: 1,
            relay_key: [relay; 32],
            relay_sig: vec![],
        }
    }

    #[test]
    fn conflicting_receipts_convict() {
        let fp = detect_conflict(&receipt(1, 2, 9), &receipt(1, 3, 9));
        assert!(fp.is_some(), "same relay, same nf, different bundles = fraud");
    }

    #[test]
    fn honest_duplicates_and_other_relays_do_not() {
        assert!(detect_conflict(&receipt(1, 2, 9), &receipt(1, 2, 9)).is_none());
        assert!(detect_conflict(&receipt(1, 2, 9), &receipt(1, 3, 8)).is_none());
        assert!(detect_conflict(&receipt(1, 2, 9), &receipt(2, 3, 9)).is_none());
    }
}
