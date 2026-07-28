//! The rolling history digest.
//!
//! `h' = H(h ‖ bundle_hash)` under [`Domain::History`], from a genesis of all
//! zeros. A note's history digest names its entire lineage in one value —
//! which is what the receiver's ancestry binding checks against
//! (`formal/multihop.qnt` `bound`: a presented ancestry must reproduce the
//! digest the proof committed to, or substitution/truncation walks right in).
//!
//! Rolling rather than accumulated: ancestor bundle hashes cannot be recovered
//! from `h`, so the ancestry itself must travel with the note (spec/04's O(n)
//! correction). The accumulator design (spec/99 [ACC]) would change that;
//! this digest is deliberately the simplest thing that binds order and content.

use p3_field::PrimeCharacteristicRing;
use uv_air::wots::Digest;

use crate::hash::{hash, Domain};

/// The digest every lineage starts from.
pub const GENESIS: Digest = [<p3_baby_bear::BabyBear as PrimeCharacteristicRing>::ZERO; 8];

/// Extend a history by one transfer.
pub fn advance(prev: &Digest, bundle_hash: &Digest) -> Digest {
    let mut input = Vec::with_capacity(16);
    input.extend_from_slice(prev);
    input.extend_from_slice(bundle_hash);
    hash(Domain::History, &input)
}

/// Fold a whole lineage, oldest first.
pub fn digest_of(bundle_hashes: &[Digest]) -> Digest {
    bundle_hashes.iter().fold(GENESIS, |h, b| advance(&h, b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn d(tag: u32) -> Digest {
        [BabyBear::from_u32(tag); 8]
    }

    #[test]
    fn order_binds() {
        assert_ne!(
            digest_of(&[d(1), d(2)]),
            digest_of(&[d(2), d(1)]),
            "a reordered lineage must be a different history"
        );
    }

    #[test]
    fn truncation_is_visible() {
        assert_ne!(digest_of(&[d(1)]), digest_of(&[d(1), d(2)]));
        assert_ne!(GENESIS, digest_of(&[d(1)]));
    }

    #[test]
    fn folding_matches_stepping() {
        let step = advance(&advance(&GENESIS, &d(7)), &d(8));
        assert_eq!(step, digest_of(&[d(7), d(8)]));
    }
}
