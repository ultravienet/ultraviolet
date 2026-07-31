//! The issuance record: what an asset's supply is made of.
//!
//! Spending publishes a 64-byte spend record ([`crate::record`]). **Issuing
//! publishes this**, and until it existed an asset's supply was whatever its
//! issuer said it was — `SPEC.md` stated outright that "issuance
//! publishes no record", and justified it purely on double-spend grounds
//! without asking what it cost auditability.
//!
//! `formal/issuance.qnt` is what settled it: under the old rule the model finds
//! secret inflation **in two steps** — mint without publishing, hand the coins
//! to a receiver, and what a holder can spend exceeds what any reader of
//! Bitcoin can see. Requiring a confirmed record closes that.
//!
//! ## Everything is in the clear, and that is the point
//!
//! ```text
//! TAG(4) ‖ amount(8, little-endian) ‖ asset(32) ‖ commitment(32)
//! ```
//!
//! The first version of this record was 44 bytes and carried
//! `H(asset ‖ commitment ‖ amount)` instead of the last two fields. That hash is
//! **one-way**, and it is the whole reason supply was only ever an *upper
//! bound*: a holder could recompute it from their own anchor and find their own
//! issuance, but nobody could ask "which records belong to asset X?". So the
//! only number anyone could compute was the sum over every asset and every
//! stranger on the chain.
//!
//! Putting the asset id in the clear makes issuances **enumerable**, and
//! `supply(X) = sum of confirmed records bearing X` is exact, computable from
//! Bitcoin alone, with nothing fetched from anywhere. That is what removed
//! `[STORAGE]` from the supply question — it is still owed, but for reissuance,
//! not for counting.
//!
//! The genesis commitment is in the clear too, and it has to be. Without it an
//! issuer mints two genesis notes of equal amount under one asset id, hands out
//! two anchors, and one record satisfies both receivers — twice the coins, one
//! record. With it, two genesis notes need two records and both are counted.
//! Truncating it to save bytes was considered and refused: the issuer picks
//! *both* notes, so a short binding is a collision problem at 2^64 rather than a
//! second-preimage one at 2^128, and that is not a trade to make on the money
//! path.
//!
//! ## Why not 64 bytes, and why the length still matters
//!
//! **A second 64-byte type would be indexed under a nullifier-shaped key.** The
//! index keys spend records on their first 32 bytes, first-occurrence wins, and
//! nothing in those 64 bytes is a version or a type tag — the whole width is
//! two digests. So an issuance record of the same length could take the slot of
//! a spend record and shadow it permanently. Length is the discriminant the
//! format has, and 76 is neither 64 nor the 44 this replaces.
//!
//! ## What is still off chain
//!
//! The declaration and the next mint key are what *reissuance* needs, and they
//! do not exist yet —
//! `uv issue` cannot add to an existing asset. See `SPEC.md`.
//!
//! One residual, stated plainly: nothing authenticates a record's asset id, so a
//! stranger can publish a **decoy** bearing someone else's asset. It inflates
//! that asset's reported number while creating no spendable coin, because no one
//! holds a note opening to their commitment. `uv supply` therefore reports
//! attested and unattested separately rather than adding them together.

use serde::{Deserialize, Serialize};
use uv_air::poseidon2::Digest;

use crate::digest::{decode, encode, DIGEST_BYTES};

/// Marks these bytes as an issuance record. ASCII `UVIS`.
///
/// Not a version field — the *length* distinguishes an issuance record from a
/// spend record. This distinguishes ours from another protocol's 76 bytes,
/// which the spend path has never been able to do and which is why the record
/// index happily accepts any 64-byte `OP_RETURN` on the chain.
pub const TAG: [u8; 4] = *b"UVIS";

/// Serialized issuance-record length.
pub const ISSUANCE_BYTES: usize = 4 + 8 + DIGEST_BYTES + DIGEST_BYTES;

/// The `scriptPubKey` length an [`ISSUANCE_BYTES`] payload produces.
///
/// `OP_RETURN` + `OP_PUSHDATA1` + one length byte + the payload. **Three bytes
/// of overhead, not two**: a direct push tops out at 75 bytes, so 76 needs
/// `OP_PUSHDATA1` — which is still the *minimal* encoding at this length, so
/// `instructions_minimal` accepts it. See
/// `an_issuance_script_is_the_minimal_encoding_of_its_length`.
pub const ISSUANCE_SCRIPT_BYTES: usize = 1 + 1 + 1 + ISSUANCE_BYTES;

/// One issuance: this much of an asset came into existence, and this is the
/// genesis note it came into existence as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuance {
    /// Units created. Public by design — this is the number being audited.
    pub amount: u64,
    /// Which asset. **In the clear, which is what makes supply countable**:
    /// without it nobody can ask which records belong to an asset.
    pub asset: Digest,
    /// The genesis note this issuance created. In the clear so that two genesis
    /// notes under one asset id cannot share a single record.
    pub commitment: Digest,
}

impl Issuance {
    /// The 76 bytes that go on chain.
    pub fn encode(&self) -> [u8; ISSUANCE_BYTES] {
        let mut out = [0u8; ISSUANCE_BYTES];
        out[..4].copy_from_slice(&TAG);
        out[4..12].copy_from_slice(&self.amount.to_le_bytes());
        out[12..44].copy_from_slice(&encode(&self.asset));
        out[44..].copy_from_slice(&encode(&self.commitment));
        out
    }

    /// Parse 76 bytes. `None` unless the tag matches and both digests are
    /// canonical — the same strictness the spend record applies, and for the
    /// same reason: bytes that cannot round-trip are malformed, not close
    /// enough, and `[ACC]` will one day make encodings consensus-visible.
    pub fn decode(bytes: &[u8; ISSUANCE_BYTES]) -> Option<Issuance> {
        if bytes[..4] != TAG {
            return None;
        }
        let mut amt = [0u8; 8];
        amt.copy_from_slice(&bytes[4..12]);
        let mut asset = [0u8; DIGEST_BYTES];
        asset.copy_from_slice(&bytes[12..44]);
        let mut commitment = [0u8; DIGEST_BYTES];
        commitment.copy_from_slice(&bytes[44..]);
        Some(Issuance {
            amount: u64::from_le_bytes(amt),
            asset: decode(&asset)?,
            commitment: decode(&commitment)?,
        })
    }
}

/// Machine-checked proofs over the production record codec (`cargo kani -p
/// uv-kernel2`). Supply is *counted* from these bytes on the public chain, so
/// the codec's claims deserve proofs, not spot checks: every record has
/// exactly one byte form, and parsing accepts nothing an encoder could not
/// have produced.
#[cfg(kani)]
mod proofs {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use uv_air::poseidon2::N;

    fn any_digest() -> Digest {
        let raw: [u32; N] = kani::any();
        for r in &raw {
            kani::assume(*r < BabyBear::ORDER_U32);
        }
        core::array::from_fn(|i| BabyBear::from_u32(raw[i]))
    }

    /// ∀ issuances — the 76 bytes round-trip exactly: what the issuer
    /// publishes is what every counter reads back.
    #[kani::proof]
    fn every_issuance_round_trips() {
        let i = Issuance {
            amount: kani::any(),
            asset: any_digest(),
            commitment: any_digest(),
        };
        assert_eq!(Issuance::decode(&i.encode()), Some(i));
    }

    /// ∀ 76-byte strings — if decode accepts them, encode reproduces them
    /// byte for byte. One record, one representation: two distinct on-chain
    /// byte strings can never claim to be the same issuance, so nothing a
    /// supply count sums is ever an alias of something it already summed.
    #[kani::proof]
    fn accepted_bytes_are_the_canonical_record() {
        let bytes: [u8; ISSUANCE_BYTES] = kani::any();
        if let Some(i) = Issuance::decode(&bytes) {
            assert_eq!(i.encode(), bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn sample() -> Issuance {
        Issuance {
            amount: 1_000_000,
            asset: [BabyBear::from_u32(11); 8],
            commitment: [BabyBear::from_u32(22); 8],
        }
    }

    #[test]
    fn it_round_trips() {
        let i = sample();
        assert_eq!(Issuance::decode(&i.encode()), Some(i));
    }

    /// The length is the type. If these ever coincide, an issuance record can
    /// be stored under a key indistinguishable from a nullifier and shadow a
    /// real spend record — which is the reason this type is not 64 bytes.
    #[test]
    fn an_issuance_record_is_not_the_length_of_a_spend_record() {
        assert_ne!(ISSUANCE_BYTES, crate::record::RECORD_BYTES);
        assert_eq!(ISSUANCE_BYTES, 76);
        assert_ne!(76, 64);
        // Nor the 44 this replaced: an index or peer holding old records must
        // fail to parse them rather than misread them under the new layout.
        assert_ne!(ISSUANCE_BYTES, 44);
    }

    /// **The margin trade, asserted rather than described.**
    ///
    /// The 44-byte record was a 46-byte script and this one is 79, against the
    /// historical 83-byte datacarrier limit — margin fell from 37 bytes to 4.
    /// That was spent deliberately, and on exactly one thing: putting the asset
    /// id and the genesis commitment in the clear, which is what turned supply
    /// from an upper bound into a total.
    ///
    /// Asserted exactly, not as `< 83`. A loose bound is how a future field
    /// gets added without anyone re-deciding this, and there are only four
    /// bytes left to spend. If policy ever tightens below 79, the fallback is
    /// the batching case `SPEC.md` already describes — the same one
    /// that answers a tightening below 64 for spend records.
    #[test]
    fn the_script_is_79_bytes_and_the_margin_was_spent_on_purpose() {
        assert_eq!(ISSUANCE_SCRIPT_BYTES, 79);
        // The margin itself, so the limit appears in the assertion rather than
        // only in prose. Written as a subtraction because `<= 83` on two
        // constants is something clippy correctly calls a tautology — the
        // interesting number is what is left, not that anything is left.
        assert_eq!(83 - ISSUANCE_SCRIPT_BYTES, 4, "the margin, stated");
    }

    /// Someone else's 76 bytes are not an issuance.
    #[test]
    fn a_foreign_payload_of_the_same_length_is_refused() {
        let mut bytes = sample().encode();
        bytes[..4].copy_from_slice(b"XXXX");
        assert_eq!(Issuance::decode(&bytes), None);
    }

    /// Same strictness as the spend record: a non-canonical digest is not a
    /// record, so it can never occupy a slot. Both fields, because checking
    /// only the first would let a malformed commitment through.
    #[test]
    fn a_non_canonical_digest_is_refused_in_either_field() {
        let mut bad_asset = sample().encode();
        bad_asset[12..16].copy_from_slice(&[0xFF; 4]);
        assert_eq!(Issuance::decode(&bad_asset), None);

        let mut bad_commitment = sample().encode();
        bad_commitment[44..48].copy_from_slice(&[0xFF; 4]);
        assert_eq!(Issuance::decode(&bad_commitment), None);
    }

    /// The amount is readable by anyone, which is the whole point: a chain
    /// reader sums these without needing anything off-chain.
    #[test]
    fn the_amount_is_in_the_clear() {
        let bytes = Issuance {
            amount: 0x0102_0304_0506_0708,
            asset: [BabyBear::ZERO; 8],
            commitment: [BabyBear::ZERO; 8],
        }
        .encode();
        assert_eq!(&bytes[4..12], &0x0102_0304_0506_0708u64.to_le_bytes());
    }

    /// **The property the whole change exists for.** A reader who holds only
    /// the chain can pick out one asset's records — no anchor, no payload, no
    /// preimage. Under the previous layout this was impossible: the record
    /// carried `H(asset ‖ commitment ‖ amount)`, and finding an asset's records
    /// meant already knowing every commitment it had ever issued under.
    #[test]
    fn an_assets_records_can_be_picked_out_of_a_mixed_chain() {
        let mine = [BabyBear::from_u32(7); 8];
        let theirs = [BabyBear::from_u32(9); 8];
        let chain = [
            Issuance {
                amount: 100,
                asset: mine,
                commitment: [BabyBear::from_u32(1); 8],
            },
            Issuance {
                amount: 500,
                asset: theirs,
                commitment: [BabyBear::from_u32(2); 8],
            },
            Issuance {
                amount: 25,
                asset: mine,
                commitment: [BabyBear::from_u32(3); 8],
            },
        ];
        let decoded: Vec<Issuance> = chain
            .iter()
            .map(|i| Issuance::decode(&i.encode()).expect("round trip"))
            .collect();
        let total: u64 = decoded
            .iter()
            .filter(|i| i.asset == mine)
            .map(|i| i.amount)
            .sum();
        assert_eq!(total, 125, "exactly this asset's issuances, nobody else's");
    }

    /// Two genesis notes under one asset id need two records, so both are
    /// counted. The inflation this closes: one record satisfying two anchors.
    #[test]
    fn two_genesis_notes_under_one_asset_cannot_share_a_record() {
        let asset = [BabyBear::from_u32(7); 8];
        let a = Issuance {
            amount: 100,
            asset,
            commitment: [BabyBear::from_u32(1); 8],
        };
        let b = Issuance {
            amount: 100,
            asset,
            commitment: [BabyBear::from_u32(2); 8],
        };
        assert_ne!(a.encode(), b.encode());
        let total: u64 = [a, b].iter().map(|i| i.amount).sum();
        assert_eq!(total, 200, "the chain reports what actually exists");
    }
}
