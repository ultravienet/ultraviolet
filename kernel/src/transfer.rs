//! Fungible transfer transitions (v1 kernel scope: issue/transfer/burn).
//!
//! [`validate_transition`] is the exact function the SP1 guest program proves:
//! it runs identically on the host (for construction and direct validation)
//! and inside the zkVM (where its execution becomes a STARK). v0 circuit
//! scope proves structure and conservation; SLH-DSA spend-authorization is
//! verified host-side and moves in-circuit in a later revision (spec/04-PROOFS.md).

use crate::hash::Hash256;
use crate::note::Note;
use crate::nullifier::Nullifier;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One spent note plus the key material needed to derive its nullifier.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpendInput {
    pub note: Note,
    pub nullifier_key: Hash256,
}

/// A fungible transfer: spend some notes, create others.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transfer {
    pub inputs: Vec<SpendInput>,
    pub outputs: Vec<Note>,
}

/// The public facts a valid transition commits to: everything a verifier
/// needs, nothing that deanonymizes the witness.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransitionResult {
    pub contract_id: Hash256,
    pub nullifiers: Vec<[u8; 32]>,
    pub output_commitments: Vec<[u8; 32]>,
}

impl TransitionResult {
    /// Canonical bytes for hashing (history digests, bundle hashes):
    /// contract_id ‖ n_nullifiers (u32 LE) ‖ nullifiers ‖
    /// n_outputs (u32 LE) ‖ commitments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + 32 * (self.nullifiers.len() + self.output_commitments.len()));
        out.extend_from_slice(&self.contract_id);
        out.extend_from_slice(&(self.nullifiers.len() as u32).to_le_bytes());
        for nf in &self.nullifiers {
            out.extend_from_slice(nf);
        }
        out.extend_from_slice(&(self.output_commitments.len() as u32).to_le_bytes());
        for c in &self.output_commitments {
            out.extend_from_slice(c);
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    NoInputs,
    NoOutputs,
    MixedContracts,
    ValueOverflow,
    NotConserved,
}

/// Validate a transfer and produce its public transition result.
///
/// Checks: non-empty sides, a single contract across every note, and exact
/// value conservation (checked arithmetic — an overflowing sum is invalid,
/// never wrapped).
pub fn validate_transition(t: &Transfer) -> Result<TransitionResult, TransitionError> {
    if t.inputs.is_empty() {
        return Err(TransitionError::NoInputs);
    }
    if t.outputs.is_empty() {
        return Err(TransitionError::NoOutputs);
    }

    let contract_id = t.inputs[0].note.contract_id;
    let all_notes = t.inputs.iter().map(|i| &i.note).chain(t.outputs.iter());
    if all_notes.clone().any(|n| n.contract_id != contract_id) {
        return Err(TransitionError::MixedContracts);
    }
    let _ = all_notes;

    let in_sum: u64 = t
        .inputs
        .iter()
        .try_fold(0u64, |acc, i| acc.checked_add(i.note.value))
        .ok_or(TransitionError::ValueOverflow)?;
    let out_sum: u64 = t
        .outputs
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or(TransitionError::ValueOverflow)?;
    if in_sum != out_sum {
        return Err(TransitionError::NotConserved);
    }

    let nullifiers = t
        .inputs
        .iter()
        .map(|i| Nullifier::derive(&i.nullifier_key, &i.note.commitment()).0)
        .collect();
    let output_commitments = t.outputs.iter().map(|o| o.commitment().0).collect();

    Ok(TransitionResult {
        contract_id,
        nullifiers,
        output_commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(contract: u8, value: u64) -> Note {
        Note {
            contract_id: [contract; 32],
            value,
            owner_key: [2; 32],
            randomness: [3; 32],
        }
    }

    fn spend(contract: u8, value: u64) -> SpendInput {
        SpendInput { note: note(contract, value), nullifier_key: [9; 32] }
    }

    #[test]
    fn one_in_two_out_conserves() {
        let t = Transfer {
            inputs: vec![spend(1, 100)],
            outputs: vec![note(1, 60), note(1, 40)],
        };
        let r = validate_transition(&t).expect("valid transfer");
        assert_eq!(r.nullifiers.len(), 1);
        assert_eq!(r.output_commitments.len(), 2);
        assert_eq!(r.contract_id, [1; 32]);
    }

    #[test]
    fn conservation_violations_rejected() {
        let t = Transfer {
            inputs: vec![spend(1, 100)],
            outputs: vec![note(1, 60), note(1, 41)],
        };
        assert_eq!(validate_transition(&t), Err(TransitionError::NotConserved));
    }

    #[test]
    fn mixed_contracts_rejected() {
        let t = Transfer {
            inputs: vec![spend(1, 100)],
            outputs: vec![note(2, 100)],
        };
        assert_eq!(validate_transition(&t), Err(TransitionError::MixedContracts));
    }

    #[test]
    fn overflow_is_invalid_not_wrapped() {
        let t = Transfer {
            inputs: vec![spend(1, u64::MAX), spend(1, 1)],
            outputs: vec![note(1, 0)],
        };
        assert_eq!(validate_transition(&t), Err(TransitionError::ValueOverflow));
    }
}
