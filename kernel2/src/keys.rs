//! Per-note keys, derived from one wallet seed.
//!
//! The one-time note-secret rule and the C2 linkability finding, made concrete: every note
//! gets its own WOTS+ signing seed, its own nullifier key, and its own
//! commitment randomness, all derived from `(wallet seed, note index)` with
//! distinct sponge domains. Consequences, each load-bearing:
//!
//! - **WOTS+ one-time discipline is per note by construction.** A note is
//!   spent once, its key signs once. (The wallet still owes the sign-log
//!   replay discipline for the in-flight window — spec/02.)
//! - **No witness secret outlives the spend it authorizes.** Nothing in one
//!   payment's witness helps forge, link, or grief any other note.
//! - **The seed alone recovers everything.** Derivation is deterministic, so
//!   "write down the seed" recovers every note's keys; only the sign log of
//!   in-flight transfers needs separate persistence (spec/02).
//!
//! The index is the wallet's own note counter. Indices may be derived sparsely
//! or densely; nothing on-chain depends on them — they exist only inside this
//! derivation.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use uv_air::wots::{Digest, N};

use crate::digest;
use crate::hash::{hash, Domain};

/// The one secret a wallet must back up.
#[derive(Clone)]
pub struct WalletSeed(pub [u8; 32]);

/// Everything a single note needs from its owner.
#[derive(Clone)]
pub struct NoteKeys {
    /// `H(nullifier_key)` — the *public* half, safe to hand a payer.
    pub anchor: Digest,
    /// Seed for this note's one-time WOTS+ keypair
    /// ([`uv_air::wots::public_key`] / [`uv_air::wots::sign`]).
    pub wots_seed: [u8; 32],
    /// Key from which this note's nullifier is derived. **Secret**: only the
    /// owner holds it. The note commits to [`NoteKeys::anchor`] instead, so a
    /// payer who builds the note cannot compute the nullifier it will one day
    /// reveal.
    pub nullifier_key: Digest,
    /// Blinding for this note's commitment.
    pub randomness: Digest,
}

/// Seed bytes as field elements: eight 4-byte little-endian chunks, reduced.
///
/// Reduction is not injective (a ~2^-124 birthday concern, not a consensus
/// one) and matches [`uv_air::wots::secret_starts`]'s treatment of the same
/// 32 bytes — one convention, everywhere.
fn seed_elements(seed: &WalletSeed) -> [BabyBear; N] {
    core::array::from_fn(|i| {
        let mut b = [0u8; 4];
        b.copy_from_slice(&seed.0[i * 4..i * 4 + 4]);
        BabyBear::from_u32(u32::from_le_bytes(b) % BabyBear::ORDER_U32)
    })
}

/// Derive note `index`'s keys from the wallet seed.
pub fn derive(seed: &WalletSeed, index: u64) -> NoteKeys {
    let s = seed_elements(seed);
    let mut input = [BabyBear::ZERO; N + 2];
    input[..N].copy_from_slice(&s);
    input[N] = BabyBear::from_u32((index & 0xFFFF_FFFF) as u32 % BabyBear::ORDER_U32);
    input[N + 1] = BabyBear::from_u32((index >> 32) as u32 % BabyBear::ORDER_U32);

    let nullifier_key = hash(Domain::NullifierKey, &input);
    NoteKeys {
        wots_seed: digest::encode(&hash(Domain::OwnerSeed, &input)),
        anchor: anchor_of(&nullifier_key),
        nullifier_key,
        randomness: hash(Domain::Randomness, &input),
    }
}

/// The public spend anchor of a nullifier key: `t = H(nk)`.
///
/// This is the value a note commits to and an address publishes. Deriving the
/// nullifier needs `nk` itself, which the anchor does not reveal — that gap is
/// the whole point, and the transfer circuit is what enforces it (the spender
/// must show a preimage of the committed anchor).
pub fn anchor_of(nullifier_key: &Digest) -> Digest {
    hash(Domain::SpendAnchor, nullifier_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notes_get_independent_keys() {
        let seed = WalletSeed([9u8; 32]);
        let a = derive(&seed, 0);
        let b = derive(&seed, 1);
        assert_ne!(a.wots_seed, b.wots_seed);
        assert_ne!(a.nullifier_key, b.nullifier_key);
        assert_ne!(a.anchor, b.anchor);
        assert_ne!(a.randomness, b.randomness);
        // And the three secrets of one note are mutually independent too.
        assert_ne!(digest::encode(&a.nullifier_key), a.wots_seed);
        assert_ne!(a.nullifier_key, a.randomness);
    }

    #[test]
    fn derivation_is_deterministic_and_seed_sensitive() {
        let seed = WalletSeed([10u8; 32]);
        assert_eq!(derive(&seed, 7).wots_seed, derive(&seed, 7).wots_seed);
        let other = WalletSeed([11u8; 32]);
        assert_ne!(derive(&seed, 7).wots_seed, derive(&other, 7).wots_seed);
    }

    #[test]
    fn high_index_bits_matter() {
        let seed = WalletSeed([12u8; 32]);
        assert_ne!(
            derive(&seed, 1).nullifier_key,
            derive(&seed, 1 << 32).nullifier_key,
            "index must be bound in full, not modulo 2^32"
        );
    }
}
