//! Nullifier derivation.
//!
//! `nf = H(nullifier_key ‖ commitment)` under [`Domain::Nullifier`].
//!
//! Deterministic in (note, owner) — audit #13 A2's requirement — so one note
//! has exactly one nullifier no matter how many spend attempts are built from
//! it, which is what makes the first-occurrence race well-defined
//! (`formal/multihop.qnt`). Deriving it needs `nullifier_key`, which only the
//! owner holds until they choose to spend: a third party cannot compute the
//! nullifier of an unspent note, so pre-emptive griefing requires the owner's
//! own broadcast (spec/99 `[FRONTRUN]` — and the record flow around that broadcast
//! is a live design question, decided at the wallet layer, not here).
//!
//! The commitment is the second input, and it binds the **anchor**
//! `t = H(nullifier_key)`. So a spender cannot pair the note with a foreign
//! key — the circuit checks that the key it derives `nf` from hashes to the
//! anchor the commitment opened to. The payer, who knows `t` but not the key,
//! cannot compute this note's nullifier at all.

use uv_air::poseidon2::Digest;

use crate::hash::{hash, Domain};
use crate::note::Note;

/// A note's nullifier, derivable only by the holder of its `nullifier_key`.
pub fn derive(nullifier_key: &Digest, commitment: &Digest) -> Digest {
    let mut input = Vec::with_capacity(16);
    input.extend_from_slice(nullifier_key);
    input.extend_from_slice(commitment);
    hash(Domain::Nullifier, &input)
}

/// A note's nullifier, given the secret key whose anchor the note commits to.
///
/// The guard is a real `assert`, not a `debug_assert`. It was the latter, which
/// compiles out of exactly the build anyone runs — the same shape as the
/// public-value check that let a forged transfer verify in `air`. Calling this
/// with someone else's key produces a nullifier that is not this note's, and
/// the wallet would publish it as though it were. One hash to rule that out.
pub fn of_note(note: &Note, nullifier_key: &Digest) -> Digest {
    assert_eq!(
        crate::keys::anchor_of(nullifier_key),
        note.nullifier_anchor,
        "the key must be this note's own"
    );
    derive(nullifier_key, &note.commitment())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::keys::{anchor_of, derive as derive_keys, WalletSeed};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn deterministic_in_note_and_owner() {
        let keys = derive_keys(&WalletSeed([3u8; 32]), 0);
        let note = Note::build([BabyBear::ZERO; 8], Amount(9), &keys);
        assert_eq!(
            of_note(&note, &keys.nullifier_key),
            of_note(&note, &keys.nullifier_key)
        );
    }

    #[test]
    fn different_notes_different_nullifiers() {
        let seed = WalletSeed([4u8; 32]);
        let ka = derive_keys(&seed, 0);
        let kb = derive_keys(&seed, 1);
        let a = Note::build([BabyBear::ZERO; 8], Amount(9), &ka);
        let b = Note::build([BabyBear::ZERO; 8], Amount(9), &kb);
        assert_ne!(
            of_note(&a, &ka.nullifier_key),
            of_note(&b, &kb.nullifier_key)
        );
    }

    #[test]
    fn a_foreign_key_does_not_produce_the_notes_nullifier() {
        let keys = derive_keys(&WalletSeed([5u8; 32]), 0);
        let foreign = derive_keys(&WalletSeed([6u8; 32]), 0);
        let note = Note::build([BabyBear::ZERO; 8], Amount(9), &keys);
        assert_ne!(
            derive(&foreign.nullifier_key, &note.commitment()),
            of_note(&note, &keys.nullifier_key)
        );
    }

    /// The payer-oracle fix, stated as a test. A payer builds the note from
    /// public material only — the anchor, never the key — so nothing it holds
    /// lets it compute the nullifier this note will one day reveal. Before the
    /// anchor existed, the note committed to the key itself and the payer kept
    /// a permanent watch on when its payment was spent.
    #[test]
    fn the_anchor_does_not_reveal_the_nullifier() {
        let keys = derive_keys(&WalletSeed([7u8; 32]), 0);
        let note = Note::build([BabyBear::ZERO; 8], Amount(50), &keys);
        // Everything the payer legitimately holds:
        let payer_knows = note.nullifier_anchor;
        assert_eq!(payer_knows, anchor_of(&keys.nullifier_key));
        // The real nullifier needs the key, which the anchor does not carry.
        let real = of_note(&note, &keys.nullifier_key);
        assert_ne!(
            derive(&payer_knows, &note.commitment()),
            real,
            "hashing the anchor must not reproduce the nullifier"
        );
    }
}
