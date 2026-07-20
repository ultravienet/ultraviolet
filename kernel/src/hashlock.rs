//! Hash-locked spend conditions (spec/06-PAYMENTS.md).
//!
//! HTLC semantics in the kernel: a note carrying a [`HashLockCondition`] is
//! spendable by revealing the SHA-256 preimage of `payment_hash` (claim
//! path), or by the refund owner after `timeout_epoch` (refund path). Pure
//! hash cryptography — post-quantum by construction — and preimage-compatible
//! with today's Lightning HTLCs, which is what makes custody-free gateway
//! swaps between Ultraviolet and Lightning atomic.
//!
//! Enforcement level: host/validation for now, like SLH-DSA spend
//! authorization; both join the guest circuit in the sig-in-circuit
//! milestone.

use crate::hash::{boundary_hash, sha256, Hash256};

const HASHLOCK_DOMAIN: &str = "uv/hashlock/v1";

/// A hash-locked note's spend condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashLockCondition {
    /// SHA-256 hash whose preimage releases the claim path. For Lightning
    /// gateway swaps this is the invoice's payment hash.
    pub payment_hash: Hash256,
    /// First epoch at which the refund path opens.
    pub timeout_epoch: u64,
    /// Owner key (hash of PQ public key) allowed to spend via refund.
    pub refund_key: Hash256,
}

impl HashLockCondition {
    /// Commitment to this condition, for embedding in a note's `owner_key`
    /// slot (a hash-locked note's "owner" is the condition itself).
    pub fn commitment(&self) -> Hash256 {
        boundary_hash(
            HASHLOCK_DOMAIN,
            &[
                &self.payment_hash,
                &self.timeout_epoch.to_le_bytes(),
                &self.refund_key,
            ],
        )
    }
}

/// Witness presented to spend a hash-locked note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashLockWitness {
    /// Claim path: the preimage of `payment_hash`.
    Preimage(Vec<u8>),
    /// Refund path: asserts the current epoch; the spend must additionally
    /// carry the refund owner's PQ signature (checked by the ordinary
    /// signature layer, `crate::sig`).
    TimeoutRefund { current_epoch: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashLockError {
    WrongPreimage,
    TimeoutNotReached,
}

/// Verify a hash-locked spend.
///
/// Claim: `sha256(preimage)` must equal the condition's payment hash.
/// Refund: the asserted epoch must have reached `timeout_epoch` (the
/// refund signature itself is verified by the signature layer).
pub fn verify_hashlock_spend(
    cond: &HashLockCondition,
    witness: &HashLockWitness,
) -> Result<(), HashLockError> {
    match witness {
        HashLockWitness::Preimage(p) => {
            if sha256(p) == cond.payment_hash {
                Ok(())
            } else {
                Err(HashLockError::WrongPreimage)
            }
        }
        HashLockWitness::TimeoutRefund { current_epoch } => {
            if *current_epoch >= cond.timeout_epoch {
                Ok(())
            } else {
                Err(HashLockError::TimeoutNotReached)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond() -> (HashLockCondition, Vec<u8>) {
        let preimage = b"lightning settlement preimage".to_vec();
        let c = HashLockCondition {
            payment_hash: sha256(&preimage),
            timeout_epoch: 100,
            refund_key: [7; 32],
        };
        (c, preimage)
    }

    #[test]
    fn correct_preimage_claims() {
        let (c, p) = cond();
        assert_eq!(verify_hashlock_spend(&c, &HashLockWitness::Preimage(p)), Ok(()));
    }

    #[test]
    fn wrong_preimage_rejected() {
        let (c, _) = cond();
        assert_eq!(
            verify_hashlock_spend(&c, &HashLockWitness::Preimage(b"wrong".to_vec())),
            Err(HashLockError::WrongPreimage)
        );
    }

    #[test]
    fn refund_gated_on_timeout() {
        let (c, _) = cond();
        assert_eq!(
            verify_hashlock_spend(&c, &HashLockWitness::TimeoutRefund { current_epoch: 99 }),
            Err(HashLockError::TimeoutNotReached)
        );
        assert_eq!(
            verify_hashlock_spend(&c, &HashLockWitness::TimeoutRefund { current_epoch: 100 }),
            Ok(())
        );
    }

    #[test]
    fn condition_commitment_binds_all_fields() {
        let (c, _) = cond();
        let mut later = c;
        later.timeout_epoch = 101;
        assert_ne!(c.commitment(), later.commitment());
        let mut other_refund = c;
        other_refund.refund_key = [8; 32];
        assert_ne!(c.commitment(), other_refund.commitment());
    }
}
