//! Notes: the unit of state (spec/02-NOTES.md).
//!
//! A note commits to `(contract_id, value, owner_key, randomness)` under a
//! domain-separated hash. Notes exist only in client-side data; the chain
//! never sees one.

use crate::hash::{boundary_hash, Hash256};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const NOTE_COMMIT_DOMAIN: &str = "uv/note-commit/v1";

/// A fungible-asset note (v1 kernel scope: issue/transfer/burn only).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Note {
    /// The contract this note belongs to (genesis hash of the asset).
    pub contract_id: Hash256,
    /// Amount, in the contract's base units.
    pub value: u64,
    /// The owner: root/hash of the note's one-time PQ spend key
    /// (SLH-DSA public key hash, or WOTS+ root in the performance profile).
    pub owner_key: Hash256,
    /// Blinding randomness; makes commitments unlinkable.
    pub randomness: Hash256,
}

/// A hiding, binding commitment to a [`Note`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NoteCommitment(pub Hash256);

impl Note {
    /// Compute this note's commitment.
    pub fn commitment(&self) -> NoteCommitment {
        NoteCommitment(boundary_hash(
            NOTE_COMMIT_DOMAIN,
            &[
                &self.contract_id,
                &self.value.to_le_bytes(),
                &self.owner_key,
                &self.randomness,
            ],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(value: u64, r: u8) -> Note {
        Note {
            contract_id: [1u8; 32],
            value,
            owner_key: [2u8; 32],
            randomness: [r; 32],
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        assert_eq!(note(100, 7).commitment(), note(100, 7).commitment());
    }

    #[test]
    fn commitment_binds_value_and_randomness() {
        assert_ne!(note(100, 7).commitment(), note(101, 7).commitment());
        assert_ne!(note(100, 7).commitment(), note(100, 8).commitment());
    }
}
