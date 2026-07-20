//! Proof-carrying-data history chaining (spec/04-PROOFS.md).
//!
//! Each hop's proof commits a [`HopOutput`] — the transition's public result,
//! a running history digest, and the guest vkey it chained under. Hop N+1
//! verifies hop N's proof *in-circuit* and advances the digest, so a receiver
//! verifies exactly one proof regardless of history depth: O(1) receive.
//!
//! Committed bytes use the fixed layout in [`HopOutput::encode`] (not serde)
//! so any hop can recompute the previous hop's public-values digest exactly.

use crate::hash::{boundary_hash, sha256, Hash256};
use crate::transfer::{Transfer, TransitionResult};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const HISTORY_DOMAIN: &str = "uv/history/v1";

/// The digest a chain starts from.
pub const GENESIS_DIGEST: Hash256 = [0u8; 32];

/// Public facts of one hop.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HopPublic {
    pub result: TransitionResult,
    pub history_digest: Hash256,
}

/// What a hop's proof commits: the hop plus the guest vkey it chained under
/// (as SP1's 8×u32 vkey words). Verifiers enforce vkey constancy across hops.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HopOutput {
    pub vkey: [u32; 8],
    pub public: HopPublic,
}

/// Guest input: start a chain, or extend one by verifying the previous proof.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HopInput {
    Genesis { transfer: Transfer, vkey: [u32; 8] },
    Chained { transfer: Transfer, prev: HopOutput, vkey: [u32; 8] },
}

/// Advance the running history digest over one transition.
pub fn advance_history(prev_digest: &Hash256, result: &TransitionResult) -> Hash256 {
    boundary_hash(HISTORY_DOMAIN, &[prev_digest, &result.canonical_bytes()])
}

/// SHA-256 of a hop's committed bytes — the exact digest
/// `verify_sp1_proof` checks for the previous hop.
pub fn public_values_digest(output: &HopOutput) -> Hash256 {
    sha256(&output.encode())
}

impl HopOutput {
    /// Fixed-layout canonical encoding (see module docs):
    /// vkey (8×u32 LE) ‖ history_digest ‖ contract_id ‖
    /// n_nullifiers (u32 LE) ‖ nullifiers ‖ n_outputs (u32 LE) ‖ commitments.
    pub fn encode(&self) -> Vec<u8> {
        let r = &self.public.result;
        let mut out = Vec::with_capacity(32 + 32 + 32 + 8 + 32 * (r.nullifiers.len() + r.output_commitments.len()));
        for w in self.vkey {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&self.public.history_digest);
        out.extend_from_slice(&r.contract_id);
        out.extend_from_slice(&(r.nullifiers.len() as u32).to_le_bytes());
        for nf in &r.nullifiers {
            out.extend_from_slice(nf);
        }
        out.extend_from_slice(&(r.output_commitments.len() as u32).to_le_bytes());
        for c in &r.output_commitments {
            out.extend_from_slice(c);
        }
        out
    }

    /// Decode [`Self::encode`]'s layout. Returns `None` on any malformation.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if bytes.len() < n {
                return None;
            }
            let (head, tail) = bytes.split_at(n);
            *bytes = tail;
            Some(head)
        }
        fn take32(bytes: &mut &[u8]) -> Option<Hash256> {
            take(bytes, 32).map(|s| s.try_into().unwrap())
        }
        fn take_u32(bytes: &mut &[u8]) -> Option<u32> {
            take(bytes, 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        }

        let mut b = bytes;
        let mut vkey = [0u32; 8];
        for w in &mut vkey {
            *w = take_u32(&mut b)?;
        }
        let history_digest = take32(&mut b)?;
        let contract_id = take32(&mut b)?;
        let n_nf = take_u32(&mut b)? as usize;
        let mut nullifiers = Vec::with_capacity(n_nf.min(1024));
        for _ in 0..n_nf {
            nullifiers.push(take32(&mut b)?);
        }
        let n_out = take_u32(&mut b)? as usize;
        let mut output_commitments = Vec::with_capacity(n_out.min(1024));
        for _ in 0..n_out {
            output_commitments.push(take32(&mut b)?);
        }
        if !b.is_empty() {
            return None;
        }
        Some(HopOutput {
            vkey,
            public: HopPublic {
                result: TransitionResult { contract_id, nullifiers, output_commitments },
                history_digest,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkageError {
    /// A spent input's commitment does not appear in the previous hop's
    /// outputs. (Demo-grade continuity: full note-accumulator membership
    /// across arbitrary DAGs is future work.)
    UnknownInput,
}

/// Check that `current` only spends notes created by `prev`.
pub fn check_linkage(prev: &TransitionResult, current: &Transfer) -> Result<(), LinkageError> {
    for input in &current.inputs {
        let c = input.note.commitment().0;
        if !prev.output_commitments.contains(&c) {
            return Err(LinkageError::UnknownInput);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Note;
    use crate::transfer::{validate_transition, SpendInput};

    fn note(value: u64, r: u8) -> Note {
        Note { contract_id: [1; 32], value, owner_key: [2; 32], randomness: [r; 32] }
    }

    fn hop1() -> (Transfer, TransitionResult) {
        let t = Transfer {
            inputs: vec![SpendInput { note: note(100, 0), nullifier_key: [9; 32] }],
            outputs: vec![note(60, 1), note(40, 2)],
        };
        let r = validate_transition(&t).unwrap();
        (t, r)
    }

    #[test]
    fn history_digest_chains_deterministically() {
        let (_, r) = hop1();
        let d1a = advance_history(&GENESIS_DIGEST, &r);
        let d1b = advance_history(&GENESIS_DIGEST, &r);
        assert_eq!(d1a, d1b);
        assert_ne!(d1a, GENESIS_DIGEST);
        let d2 = advance_history(&d1a, &r);
        assert_ne!(d2, d1a, "digest must advance every hop");
    }

    #[test]
    fn linkage_accepts_spends_of_prev_outputs_and_rejects_strangers() {
        let (_, r1) = hop1();
        let good = Transfer {
            inputs: vec![SpendInput { note: note(60, 1), nullifier_key: [8; 32] }],
            outputs: vec![note(60, 3)],
        };
        assert_eq!(check_linkage(&r1, &good), Ok(()));

        let bad = Transfer {
            inputs: vec![SpendInput { note: note(60, 99), nullifier_key: [8; 32] }],
            outputs: vec![note(60, 3)],
        };
        assert_eq!(check_linkage(&r1, &bad), Err(LinkageError::UnknownInput));
    }

    #[test]
    fn hop_output_encoding_roundtrips() {
        let (_, r) = hop1();
        let out = HopOutput {
            vkey: [1, 2, 3, 4, 5, 6, 7, 8],
            public: HopPublic { history_digest: advance_history(&GENESIS_DIGEST, &r), result: r },
        };
        let bytes = out.encode();
        assert_eq!(HopOutput::decode(&bytes), Some(out));
        assert_eq!(HopOutput::decode(&bytes[..bytes.len() - 1]), None, "truncation rejected");
    }
}
