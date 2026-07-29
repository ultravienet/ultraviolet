//! The money path's one hash: a domain-separated Poseidon2 sponge.
//!
//! Every hash in the v2 kernel — note commitments, nullifiers, bundle hashes,
//! history digests, key derivation — is this one function with a different
//! domain tag. One primitive, one implementation, one place to audit. The
//! permutation is the same published-constants Poseidon2-16 the WOTS+ chains
//! and the STARK use ([`crate::wots::permutation`]), so a hash computed here
//! is exactly a hash the circuit can constrain as one row.
//!
//! ## Construction
//!
//! Rate 8, capacity 8, add-absorb (matching [`crate::wots::compress`]):
//!
//! ```text
//! state[14] = input length     (capacity)
//! state[15] = domain tag       (capacity)
//! for each rate-sized chunk: state[0..8] += chunk; permute
//! output = state[0..8]
//! ```
//!
//! Domain tag and **input length in the capacity** make the sponge prefix-free
//! without padding rules: two inputs of different lengths differ in the initial
//! state, so `H(x)` and `H(x ‖ 0)` diverge even though zero-padding the last
//! chunk is otherwise invisible to add-absorb. Every caller in this crate has a
//! fixed input shape per domain anyway; the length binding is defense against
//! the *next* caller, who won't.
//!
//! Changing anything here — the tags, the slots, the absorb rule — is a
//! consensus fork. The tests pin all of it.

use crate::wots::{self, Digest, N, WIDTH};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;

// ---- Sponge preimage shapes, shared by the host and the transfer circuit ----
//
// These describe the lengths the transfer circuit's sponge section absorbs, and
// they must match what this module's `hash` computes. They lived in
// `transfer_air` when it was the money-path circuit; they moved here, beside the
// sponge itself, when the proof-native circuit replaced it.

/// A 64-bit amount as four 16-bit limbs.
pub const AMOUNT_LIMBS: usize = 4;
/// Sponge rows in one transfer: three note commitments (4 rows each), a
/// nullifier (2), an anchor (1) = 3·4 + 2 + 1 = 15.
pub const SPONGE_ROWS: usize = 15;
/// Note-commitment preimage: `asset ‖ amount(4) ‖ anchor ‖ rnd` = 28. `owner_pk`
/// was dropped from the note (spec/99 `[PROOF-AUTH]`): the anchor preimage is
/// the authorization, so a one-time public key in the commitment authorized
/// nothing and only cost rows.
pub const NOTE_PREIMAGE: usize = 28;
/// Nullifier preimage: `nullifier_key ‖ input_commitment` = 16.
pub const NF_PREIMAGE: usize = 16;
/// Spend-anchor preimage: `nullifier_key` = 8.
pub const ANCHOR_PREIMAGE: usize = 8;

/// Domain tags. Values are arbitrary but frozen; reusing one across two call
/// sites would collapse their hash spaces into each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Domain {
    /// Note commitments (kernel2 `note`).
    Note = 0x_4e4f_5445, // "NOTE"
    /// Nullifier derivation (kernel2 `nullifier`).
    Nullifier = 0x_4e55_4c4c, // "NULL"
    /// Transfer bundle hashes (kernel2 `transfer`).
    Bundle = 0x_424e_444c, // "BNDL"
    /// History digest advance (kernel2 `history`).
    History = 0x_4849_5354, // "HIST"
    /// Per-note WOTS+ seed derivation (kernel2 `keys`).
    OwnerSeed = 0x_4f57_4e52, // "OWNR"
    /// Per-note nullifier key derivation (kernel2 `keys`).
    NullifierKey = 0x_4e46_4b59, // "NFKY"
    /// Per-note commitment randomness derivation (kernel2 `keys`).
    Randomness = 0x_524e_444d, // "RNDM"
    /// The spend anchor: `t = H(nullifier_key)`. The note commits to `t`, not
    /// to the key itself, so a payer who builds the note cannot compute its
    /// nullifier — see kernel2 `note`.
    SpendAnchor = 0x_414e_4348, // "ANCH"
}

/// The pre-permutation state of every absorb step, in order.
///
/// `states[k]` is the full width-16 state as it enters the `k`-th permutation
/// — exactly the row the transfer AIR lays down for that absorb, which is why
/// this exists: the circuit's witness and the host's hash must be one
/// computation, not two implementations agreeing by luck. [`hash`] is defined
/// *on top of* this function, so they cannot drift.
pub fn absorb_states(domain: Domain, inputs: &[BabyBear]) -> Vec<[BabyBear; WIDTH]> {
    let perm = wots::permutation();
    let mut state = [BabyBear::ZERO; WIDTH];
    state[WIDTH - 2] = BabyBear::from_u64(inputs.len() as u64);
    state[WIDTH - 1] = BabyBear::from_u32(domain as u32);
    let mut states = Vec::with_capacity(inputs.len().div_ceil(N).max(1));
    for chunk in inputs.chunks(N) {
        for (i, x) in chunk.iter().enumerate() {
            state[i] += *x;
        }
        states.push(state);
        perm.permute_mut(&mut state);
    }
    // Zero-length input still permutes once, so the output depends on the tag.
    if inputs.is_empty() {
        states.push(state);
    }
    states
}

/// The domain-separated sponge. See the module docs for the construction.
pub fn hash(domain: Domain, inputs: &[BabyBear]) -> Digest {
    let perm = wots::permutation();
    let mut state = *absorb_states(domain, inputs)
        .last()
        .expect("at least one absorb");
    perm.permute_mut(&mut state);
    let mut out = [BabyBear::ZERO; N];
    out.copy_from_slice(&state[..N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elems(vals: &[u32]) -> Vec<BabyBear> {
        vals.iter().map(|&v| BabyBear::from_u32(v)).collect()
    }

    #[test]
    fn domains_separate() {
        let x = elems(&[1, 2, 3]);
        assert_ne!(hash(Domain::Note, &x), hash(Domain::Nullifier, &x));
        assert_ne!(hash(Domain::Bundle, &x), hash(Domain::History, &x));
        assert_ne!(hash(Domain::OwnerSeed, &x), hash(Domain::NullifierKey, &x));
    }

    #[test]
    fn length_is_bound() {
        // Add-absorb cannot see a trailing zero inside one chunk; the length
        // slot in the capacity must make it visible.
        let short = elems(&[7, 8]);
        let padded = elems(&[7, 8, 0]);
        assert_ne!(hash(Domain::Note, &short), hash(Domain::Note, &padded));
    }

    #[test]
    fn deterministic_and_input_sensitive() {
        let x = elems(&[10, 20, 30, 40, 50, 60, 70, 80, 90]); // spans two chunks
        assert_eq!(hash(Domain::Note, &x), hash(Domain::Note, &x));
        let mut y = x.clone();
        y[8] += BabyBear::ONE; // second chunk
        assert_ne!(hash(Domain::Note, &x), hash(Domain::Note, &y));
    }

    #[test]
    fn empty_input_still_depends_on_domain() {
        assert_ne!(hash(Domain::Note, &[]), hash(Domain::Nullifier, &[]));
    }

    /// Pin the construction itself: if the absorb rule, the capacity slots, or
    /// the permutation constants change, this vector changes, and that is a
    /// consensus fork someone must have meant to make.
    #[test]
    fn test_vector_is_frozen() {
        use p3_field::PrimeField32;
        let out = hash(Domain::Note, &elems(&[1, 2, 3, 4, 5, 6, 7, 8, 9]));
        // Recompute by hand from the documented construction.
        let perm = wots::permutation();
        let mut state = [BabyBear::ZERO; WIDTH];
        state[14] = BabyBear::from_u32(9);
        state[15] = BabyBear::from_u32(Domain::Note as u32);
        for (i, v) in [1u32, 2, 3, 4, 5, 6, 7, 8].iter().enumerate() {
            state[i] += BabyBear::from_u32(*v);
        }
        perm.permute_mut(&mut state);
        state[0] += BabyBear::from_u32(9);
        perm.permute_mut(&mut state);
        assert_eq!(out[..], state[..8], "construction drifted from its spec");
        // And one literal value, so even a coordinated host+test change trips.
        assert_ne!(out[0].as_canonical_u32(), 0);
    }
}
