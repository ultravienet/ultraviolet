//! Nullifiers and the 64-byte on-chain record (spec/03-RECORDS.md).
//!
//! ```text
//! nf     = H(nullifier_key ‖ note_commitment)   // deterministic per note
//! record = nf ‖ H(transfer_bundle)              // 64 bytes on-chain
//! ```
//!
//! Consensus rule (enforced client-side): a spend of note N is valid iff the
//! FIRST on-chain occurrence of nf(N) carries a bundle hash matching the
//! transfer. Same nf for any conflicting spend + first-wins ordering + the
//! pinned bundle hash = double-spend and equivocation prevention with nothing
//! on-chain a quantum computer can attack.

use crate::hash::{boundary_hash, Hash256};
use crate::note::NoteCommitment;

const NULLIFIER_DOMAIN: &str = "uv/nf/v1";
const BUNDLE_DOMAIN: &str = "uv/bundle/v1";

/// Deterministic per-note nullifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Nullifier(pub Hash256);

impl Nullifier {
    /// Derive the nullifier for a note. `nullifier_key` is held by the note
    /// owner; the derivation is deterministic so any two spends of the same
    /// note collide on-chain.
    pub fn derive(nullifier_key: &Hash256, commitment: &NoteCommitment) -> Self {
        Nullifier(boundary_hash(NULLIFIER_DOMAIN, &[nullifier_key, &commitment.0]))
    }
}

/// Hash of a serialized transfer bundle.
pub fn bundle_hash(bundle_bytes: &[u8]) -> Hash256 {
    boundary_hash(BUNDLE_DOMAIN, &[bundle_bytes])
}

/// The 64-byte record published on Bitcoin (inline mode) or as a
/// Merkle-batch leaf (batched mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub nf: Nullifier,
    pub bundle_hash: Hash256,
}

impl Record {
    pub const SIZE: usize = 64;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.nf.0);
        out[32..].copy_from_slice(&self.bundle_hash);
        out
    }

    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let mut nf = [0u8; 32];
        let mut bh = [0u8; 32];
        nf.copy_from_slice(&bytes[..32]);
        bh.copy_from_slice(&bytes[32..]);
        Record { nf: Nullifier(nf), bundle_hash: bh }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Note;

    #[test]
    fn nullifier_is_deterministic_per_note() {
        let n = Note {
            contract_id: [1; 32],
            value: 5,
            owner_key: [2; 32],
            randomness: [3; 32],
        };
        let nk = [9u8; 32];
        let a = Nullifier::derive(&nk, &n.commitment());
        let b = Nullifier::derive(&nk, &n.commitment());
        assert_eq!(a, b, "two spends of one note must collide on nf");
    }

    #[test]
    fn record_roundtrips_at_64_bytes() {
        let r = Record { nf: Nullifier([7; 32]), bundle_hash: [8; 32] };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(Record::from_bytes(&bytes), r);
    }
}
