//! Amounts: u64 on the host, four 16-bit limbs in the field.
//!
//! BabyBear is a ~31-bit field, so a u64 value cannot ride in one element and
//! `Σ limb_i · 2^(16·i)` cannot be evaluated in-field without wrapping. The
//! representation is therefore **four 16-bit limbs, little-endian**, and every
//! consumer treats them as such:
//!
//! - host arithmetic is checked `u64` — an overflowing sum is invalid, never
//!   wrapped (same rule as the old kernel's `checked arithmetic`);
//! - in-circuit, each limb is range-checked to 16 bits by boolean bits, and
//!   conservation is limb-wise with carries (the transfer AIR's job);
//! - 16 bits per limb, not 31, precisely so that sums of a handful of limbs
//!   stay far below p and carry handling stays a 1-bit affair.
//!
//! [`Amount::from_limbs`] rejects out-of-range limbs for the same reason
//! [`crate::digest::decode`] rejects non-canonical bytes: one value, one
//! representation, no aliases.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};

/// Limbs per amount.
pub const LIMBS: usize = 4;
/// Bits per limb.
pub const LIMB_BITS: usize = 16;

/// A quantity of an asset. Construct from a `u64`; convert to limbs at the
/// field boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// The field representation: four 16-bit little-endian limbs.
    pub fn limbs(&self) -> [BabyBear; LIMBS] {
        core::array::from_fn(|i| BabyBear::from_u32(((self.0 >> (LIMB_BITS * i)) & 0xFFFF) as u32))
    }

    /// Rebuild from limbs. `None` if any limb is outside 16 bits — an aliased
    /// representation the protocol must refuse, not normalize.
    pub fn from_limbs(limbs: &[BabyBear; LIMBS]) -> Option<Amount> {
        let mut v: u64 = 0;
        for (i, limb) in limbs.iter().enumerate() {
            let raw = limb.as_canonical_u32();
            if raw >= 1 << LIMB_BITS {
                return None;
            }
            v |= u64::from(raw) << (LIMB_BITS * i);
        }
        Some(Amount(v))
    }

    /// Checked addition: `None` on overflow, which callers must treat as an
    /// invalid transfer, never a wrapped one.
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Checked subtraction: `None` on underflow.
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

/// Sum a slice with checked arithmetic. `None` if any step overflows.
pub fn checked_sum(amounts: &[Amount]) -> Option<Amount> {
    amounts
        .iter()
        .try_fold(Amount(0), |acc, a| acc.checked_add(*a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbs_round_trip() {
        for v in [
            0u64,
            1,
            0xFFFF,
            0x1_0000,
            u64::MAX,
            21_000_000 * 100_000_000,
        ] {
            let a = Amount(v);
            assert_eq!(Amount::from_limbs(&a.limbs()), Some(a));
        }
    }

    #[test]
    fn oversized_limbs_are_rejected() {
        let mut limbs = Amount(5).limbs();
        limbs[0] = BabyBear::from_u32(1 << LIMB_BITS);
        assert_eq!(Amount::from_limbs(&limbs), None);
    }

    /// The circuit lays out amounts as a fixed number of limb columns. If that
    /// number ever disagrees with this one, the circuit range-checks and
    /// conserves a different quantity than the host serializes — silently, and
    /// on the money path. `transfer_air.rs` claimed a test pinned this; none
    /// did, until an audit noticed. This is that test.
    #[test]
    fn the_circuit_agrees_on_how_many_limbs_an_amount_has() {
        assert_eq!(LIMBS, uv_air::transfer_air::AMOUNT_LIMBS);
        assert_eq!(Amount(u64::MAX).limbs().len(), LIMBS);
        // ...and the limbs must actually span the whole amount, or values above
        // the span would be unrepresentable rather than rejected.
        assert_eq!(LIMBS * LIMB_BITS, 64);
    }

    #[test]
    fn sums_are_checked_not_wrapped() {
        assert_eq!(
            checked_sum(&[Amount(u64::MAX), Amount(1)]),
            None,
            "overflow must be invalid, never wrapped"
        );
        assert_eq!(
            checked_sum(&[Amount(2), Amount(3), Amount(5)]),
            Some(Amount(10))
        );
    }
}
