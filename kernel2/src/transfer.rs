//! Transfers and the bundle hash — the WOTS+ message.
//!
//! v1 shape: **exactly one input, exactly two outputs** (see [`OUTPUTS`]).
//! Multi-input spends stay refused until merging ships with its atomicity
//! story (`formal/baserail.qnt` `splitRecords`; spec/99 [MERGE]).
//!
//! The bundle hash binds the input's commitment and nullifier, every output
//! commitment, and the **history digest the spender starts from**. It is the
//! one message the input note's WOTS+ key ever signs, so everything a receiver
//! must not let the sender re-negotiate has to be inside it:
//!
//! - outputs: or the signature could be replayed onto different payees;
//! - the nullifier: binds which spend this is;
//! - `prev_history`: pins the transfer to one position in one history, so an
//!   identical payment shape in another lineage is a different message.
//!
//! The canonical encoding is length-tagged by the sponge itself
//! ([`crate::hash`]), so one- and two-output transfers can never collide.

use serde::{Deserialize, Serialize};
use uv_air::wots::Digest;

/// Outputs per transfer: **exactly** payment + change, always.
///
/// Fixed rather than 1..=2 because the transfer circuit proves one uniform
/// shape, and a shape the circuit cannot prove would be unpayable anyway. A
/// one-recipient payment carries a genuine zero-amount change note (fresh
/// keys and randomness, owned by the sender) — which also uniformizes what an
/// observer sees: every hop has two outputs, and a dummy is indistinguishable
/// from real change.
pub const OUTPUTS: usize = 2;

/// A single-input transfer, as validated by receivers and signed by senders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    /// Commitment of the note being spent.
    pub input_commitment: Digest,
    /// The input note's nullifier ([`crate::nullifier`]).
    pub nullifier: Digest,
    /// Output note commitments, exactly [`OUTPUTS`], order-significant.
    pub outputs: Vec<Digest>,
    /// The history digest this transfer extends ([`crate::history`]).
    pub prev_history: Digest,
}

/// Why a transfer's shape is invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum BadShape {
    /// Not exactly [`OUTPUTS`] outputs.
    WrongOutputCount,
}

impl Transfer {
    /// Shape check: every consumer calls this before anything else.
    pub fn check_shape(&self) -> Result<(), BadShape> {
        if self.outputs.len() != OUTPUTS {
            return Err(BadShape::WrongOutputCount);
        }
        Ok(())
    }

    /// The bundle hash: what the record commits to, and the exact message the
    /// input note's WOTS+ key signs.
    ///
    /// Delegates to `uv_air::prove::bundle_hash`, which is the single
    /// definition — the statement a proof is checked against derives its
    /// message the same way, so the signed thing and the validated thing cannot
    /// drift apart.
    pub fn bundle_hash(&self) -> Digest {
        uv_air::prove::bundle_hash(
            &self.input_commitment,
            &self.nullifier,
            &self.prev_history,
            &self.outputs,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn d(tag: u32) -> Digest {
        [BabyBear::from_u32(tag); 8]
    }

    fn base() -> Transfer {
        Transfer {
            input_commitment: d(1),
            nullifier: d(2),
            outputs: vec![d(3)],
            prev_history: d(4),
        }
    }

    #[test]
    fn shape_is_enforced() {
        let mut t = base();
        t.outputs = vec![];
        assert_eq!(t.check_shape(), Err(BadShape::WrongOutputCount));
        t.outputs = vec![d(3)];
        assert_eq!(
            t.check_shape(),
            Err(BadShape::WrongOutputCount),
            "one output is not a provable shape; use a zero-amount change note"
        );
        t.outputs = vec![d(3), d(5), d(6)];
        assert_eq!(t.check_shape(), Err(BadShape::WrongOutputCount));
        t.outputs = vec![d(3), d(5)];
        assert_eq!(t.check_shape(), Ok(()));
    }

    #[test]
    fn every_field_binds_the_bundle_hash() {
        let t = base();
        let h = t.bundle_hash();

        let mut m = t.clone();
        m.input_commitment = d(9);
        assert_ne!(m.bundle_hash(), h);

        let mut m = t.clone();
        m.nullifier = d(9);
        assert_ne!(m.bundle_hash(), h);

        let mut m = t.clone();
        m.outputs = vec![d(9)];
        assert_ne!(
            m.bundle_hash(),
            h,
            "payee substitution must change the message"
        );

        let mut m = t.clone();
        m.prev_history = d(9);
        assert_ne!(m.bundle_hash(), h, "history position must bind");

        let mut m = t.clone();
        m.outputs.push(d(5));
        assert_ne!(m.bundle_hash(), h, "adding change must change the message");

        // Order matters: paying A with change B is not paying B with change A.
        let mut ab = t.clone();
        ab.outputs = vec![d(3), d(5)];
        let mut ba = t;
        ba.outputs = vec![d(5), d(3)];
        assert_ne!(ab.bundle_hash(), ba.bundle_hash());
    }
}
