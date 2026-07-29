//! The v2 kernel: Ultraviolet's money path, field-native on Poseidon2.
//!
//! Everything here obeys three rules the v1 kernel could not:
//!
//! 1. **One hash.** Every commitment, nullifier, bundle hash, digest, and key
//!    derivation is the same domain-separated Poseidon2 sponge ([`hash`]),
//!    over the same permutation the sovereign STARK constrains at one row per
//!    call. "Hashes only on the money path" — and only this one.
//! 2. **Per-note secrets.** Keys, nullifier keys, and randomness are derived
//!    per note ([`keys`]); no witness secret outlives the spend it authorizes,
//!    and WOTS+'s one-time rule is per-note by construction.
//! 3. **One representation per value.** Byte decodings reject non-canonical
//!    field limbs ([`digest`]), amount limbs reject out-of-range values
//!    ([`amount`]), and the sponge binds input length — no aliases anywhere a
//!    consensus rule keys on bytes.
//!
//! The record format is v1's, unchanged in shape: 64 bytes, `nf ‖ H(bundle)`,
//! first occurrence wins ([`record`]). Every model in `formal/` carries over.
//!
//! The old `kernel` crate (SHA-256, SLH-DSA, SP1's patched sha2) remains in
//! the tree untouched until nothing imports it; this crate shares no types
//! with it, on purpose.

pub mod amount;
pub mod digest;
pub mod hash;
pub mod history;
pub mod issuance;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod record;
pub mod transfer;
pub mod transfer_prove;

#[cfg(test)]
mod hop_test {
    //! One full hop, host-side: the money path end to end, no circuit.

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use crate::amount::{checked_sum, Amount};
    use crate::history;
    use crate::keys::{derive, WalletSeed};
    use crate::note::Note;
    use crate::nullifier;
    use crate::record::Record;
    use crate::transfer::Transfer;

    #[test]
    fn a_full_hop_holds_together() {
        let asset = [BabyBear::from_u32(0xC0117AC7); 8];

        // Alice's note 0, issued at genesis with 100 units.
        let alice = WalletSeed([21u8; 32]);
        let alice_keys = derive(&alice, 0);
        let note = Note::build(asset, Amount(100), &alice_keys);

        // She pays Bob 60 and keeps 40 in change.
        let bob_keys = derive(&WalletSeed([22u8; 32]), 0);
        let payment = Note::build(asset, Amount(60), &bob_keys);
        let change_keys = derive(&alice, 1);
        let change = Note::build(asset, Amount(40), &change_keys);
        assert_eq!(
            checked_sum(&[payment.amount, change.amount]),
            Some(note.amount),
            "conservation"
        );

        let transfer = Transfer {
            input_commitment: note.commitment(),
            nullifier: nullifier::of_note(&note, &alice_keys.nullifier_key),
            outputs: vec![payment.commitment(), change.commitment()],
            prev_history: history::GENESIS,
        };
        transfer.check_shape().unwrap();

        // Authorization is the anchor preimage proven in-circuit (spec/99
        // `[PROOF-AUTH]`), not a signature — the note's key signs nothing. Spend
        // authorization is `transfer_prove` and `conformance_authorization`'s to
        // test; this test is about the host types holding together across a hop.
        let msg = transfer.bundle_hash();

        // The record that goes on chain, and the history Bob's note carries.
        let record = Record {
            nullifier: transfer.nullifier,
            bundle_hash: msg,
        };
        assert_eq!(Record::decode(&record.encode()), Some(record));
        let new_history = history::advance(&transfer.prev_history, &msg);
        assert_ne!(new_history, history::GENESIS);
    }
}
