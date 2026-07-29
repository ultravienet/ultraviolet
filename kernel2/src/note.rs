//! Notes and their commitments.
//!
//! A note is `(asset, amount, owner_pk, nullifier_key, randomness)`; what the
//! world sees is its commitment, a single digest. The commitment binds every
//! field, so the transfer circuit can open it and prove statements about the
//! contents without revealing them — and so no two distinct notes share a
//! commitment short of a sponge collision.
//!
//! The note carries **no `owner_pk`** (spec/99 `[PROOF-AUTH]`): authorization is
//! the anchor preimage proven in-circuit, so a one-time public key in the
//! commitment authorized nothing and only cost sponge rows. It was removed when
//! the WOTS+ signature left the money path.
//!
//! The commitment binds the **spend anchor** `t = H(nullifier_key)`, not the
//! nullifier key itself. Two things follow, and both matter:
//!
//! - The nullifier's derivation is still pinned to this note, so a spend
//!   cannot swap in a different key and mint a fresh nullifier for a note that
//!   is already spent. The circuit checks the spender knows a preimage of `t`.
//! - **A payer cannot compute the nullifier of the note it pays.** Everything a
//!   payer needs to build the note is public (`t` included); the key that
//!   derives the nullifier is not. Before this, a payer who handed over
//!   `nullifier_key` kept a permanent watch on when that note was spent.

use serde::{Deserialize, Serialize};
use uv_air::wots::Digest;

use crate::amount::Amount;
use crate::hash::{hash, Domain};
use crate::keys::NoteKeys;

/// Sponge input length of a commitment: asset + 4 amount limbs + nullifier
/// anchor + randomness.
const COMMIT_INPUT: usize = 8 + 4 + 8 + 8;

/// A note in the open — the spender's view. Receivers of a payment hold the
/// note; everyone else holds only [`Note::commitment`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// The asset this note carries units of (a contract id at genesis).
    pub asset: Digest,
    pub amount: Amount,
    /// The spend anchor `t = H(nullifier_key)` ([`crate::keys::anchor_of`]).
    /// Public: safe to publish in an address and hand to a payer. This — not any
    /// public key — is what authorizes a spend, in-circuit.
    pub nullifier_anchor: Digest,
    /// Commitment blinding.
    pub randomness: Digest,
}

impl Note {
    /// Build a note owned by `keys`.
    pub fn build(asset: Digest, amount: Amount, keys: &NoteKeys) -> Note {
        Note {
            asset,
            amount,
            nullifier_anchor: keys.anchor,
            randomness: keys.randomness,
        }
    }

    /// The commitment: what records, transfers, and ancestries refer to.
    pub fn commitment(&self) -> Digest {
        let mut input = Vec::with_capacity(COMMIT_INPUT);
        input.extend_from_slice(&self.asset);
        input.extend_from_slice(&self.amount.limbs());
        input.extend_from_slice(&self.nullifier_anchor);
        input.extend_from_slice(&self.randomness);
        debug_assert_eq!(input.len(), COMMIT_INPUT);
        hash(Domain::Note, &input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{derive, WalletSeed};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn asset() -> Digest {
        [BabyBear::from_u32(0xA55E7); 8]
    }

    #[test]
    fn every_field_binds_the_commitment() {
        let keys = derive(&WalletSeed([1u8; 32]), 0);
        let note = Note::build(asset(), Amount(100), &keys);
        let base = note.commitment();

        let mut n = note.clone();
        n.amount = Amount(101);
        assert_ne!(n.commitment(), base, "amount must bind");

        let mut n = note.clone();
        n.asset[0] += BabyBear::ONE;
        assert_ne!(n.commitment(), base, "asset must bind");

        let mut n = note.clone();
        n.nullifier_anchor[0] += BabyBear::ONE;
        assert_ne!(n.commitment(), base, "spend anchor must bind");

        let mut n = note;
        n.randomness[0] += BabyBear::ONE;
        assert_ne!(n.commitment(), base, "randomness must bind");
    }

    #[test]
    fn same_note_same_commitment() {
        let keys = derive(&WalletSeed([2u8; 32]), 3);
        let a = Note::build(asset(), Amount(5), &keys);
        let b = Note::build(asset(), Amount(5), &keys);
        assert_eq!(a.commitment(), b.commitment());
    }
}
