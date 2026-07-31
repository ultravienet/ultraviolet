//! The Poseidon2 instance and the digest type every crate shares.
//!
//! Four items, and they are what the rest of the workspace imports: the state
//! [`WIDTH`], the rate [`N`], the [`Digest`] type, and the [`permutation`]
//! itself. Everything money-path is built on these — commitments, nullifiers,
//! anchors, asset ids, records — through the one sponge in [`crate::sponge`].
//!
//! There is no second construction here and that is load-bearing: `sponge.rs`
//! claims one primitive with one place to audit, and the claim is only true
//! while this file stays this small.

use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear, Poseidon2BabyBear};

/// Poseidon2 state width. The sponge's rate is [`N`] and its capacity is the
/// remaining `WIDTH - N` lanes (`sponge.rs`).
pub const WIDTH: usize = 16;

/// Digest width in field elements: 8 × ~31 bits ≈ 248 bits.
///
/// The security margin this implies is a recorded decision rather than an
/// accident — `SPEC.md` §5.4 and spec/99 `[SPONGE-MARGIN]`.
pub const N: usize = 8;

/// A money-path digest: commitments, nullifiers, anchors, asset ids, records.
pub type Digest = [BabyBear; N];

/// The sponge needs a non-empty capacity, checked at **compile** time.
///
/// This was a runtime `assert!` in a test until clippy pointed out — correctly,
/// and for the second time today — that both sides are compile-time constants,
/// so it could never fail at run time. As a `const` assertion it fails the build,
/// which is what a layout invariant deserves.
const _: () = assert!(N < WIDTH, "rate N must leave a capacity of WIDTH - N lanes");

/// Build the permutation with **published, fixed** round constants.
///
/// Deliberately not `from_rng`: host and circuit must agree on constants, and a
/// protocol cannot have per-instance ones. The literal output is frozen in
/// `air/tests/known_answer_vectors.rs`, which is the only artifact that would
/// notice an upstream constant change — the differential tests compare our
/// vendored copy against the same crate the constants come from, so both sides
/// would move together and stay green.
pub fn permutation() -> Poseidon2BabyBear<WIDTH> {
    default_babybear_poseidon2_16()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::Permutation;

    /// Distinct inputs stay distinct across the permutation.
    ///
    /// Deliberately thin. What actually pins this instance is
    /// `air/tests/known_answer_vectors.rs` (literal outputs) and
    /// `air/tests/poseidon2_differential.rs` (the in-circuit evaluation against
    /// the host, and the linear layers against the paper).
    #[test]
    fn the_permutation_is_injective_on_a_sample() {
        let perm = permutation();
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u32 {
            let mut st = [BabyBear::ZERO; WIDTH];
            st[0] = BabyBear::from_u32(i);
            perm.permute_mut(&mut st);
            let key: Vec<u32> = st
                .iter()
                .map(p3_field::PrimeField32::as_canonical_u32)
                .collect();
            assert!(
                seen.insert(key),
                "two distinct inputs permuted to one state"
            );
        }
    }

    #[test]
    fn the_shapes_are_what_every_crate_assumes() {
        let d: Digest = [BabyBear::ZERO; N];
        assert_eq!(d.len(), 8);
        assert_eq!(N, 8);
        assert_eq!(WIDTH, 16);
    }
}
