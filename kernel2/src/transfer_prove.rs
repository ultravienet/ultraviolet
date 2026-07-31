//! Proving and verifying transfers with real notes — the consensus wrapper.
//!
//! [`verify_hiding`] is **the** verification procedure for a hop. It derives the
//! public statement from the [`Transfer`] being validated — the bundle hash
//! above all, which is what makes the proof *this transfer's* proof — then hands
//! off to `uv_air`'s STARK verify. Calling the lower layers with a
//! hand-assembled statement proves nothing about any transfer; that is why this
//! module exists.
//!
//! [`prove_hiding`] is the sender's side: it builds the transfer from real notes
//! and lays the witness down for the circuit. **Authorization is the anchor
//! preimage, not a signature** (spec/99 `[PROOF-AUTH]`): the spender exhibits,
//! in-circuit, a hash preimage of the anchor `t = H(nullifier_key)` its note
//! committed to, bound to this exact transfer because every public value — the
//! bundle hash included — enters the Fiat–Shamir transcript. Nothing signs, so
//! there is no one-time key to disclose and proving twice reveals nothing; the
//! sign-log, the replay-instead-of-resign discipline, and slot reservations as
//! fund-critical state are all gone with the signature.
//!
//! The witness — the nullifier key — enters every spend proof, so
//! zero-knowledge is load-bearing for **funds**, not just privacy: the hiding
//! configuration is the only configuration on the money path. Anchors stay
//! one-time per note, so a witness leak's blast radius is one note.
//!
//! The note carries **no `owner_pk`**: a one-time public key in the commitment
//! authorized nothing once the signature was gone, so it was dropped, shrinking
//! the note preimage to 28 field elements and the transfer trace to 16 rows.

use uv_air::poseidon2::Digest;
use uv_air::prove::{
    prove_authproto_hiding, verify_authproto_hiding, HidingAuthProtoProof, HidingConfig, Rejected,
    TransferPublics, VerifyError, Vouched,
};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

use crate::keys::NoteKeys;
use crate::note::Note;
use crate::nullifier;
use crate::transfer::{BadShape, Transfer};

/// A note's opening for the circuit. `nullifier_key` is the secret whose anchor
/// the note commits to — the spender must supply it, which is exactly what the
/// circuit's anchor row checks. Output notes are built by a payer who does not
/// hold theirs, so they pass a zero placeholder the circuit never reads (only
/// the input's key is constrained).
fn opening(note: &Note, nullifier_key: &Digest) -> NoteOpening {
    NoteOpening {
        amount_limbs: note.amount.limbs(),
        nullifier_key: *nullifier_key,
        anchor: note.nullifier_anchor,
        randomness: note.randomness,
    }
}

/// Placeholder key for an output opening: the circuit constrains only the input
/// note's anchor preimage.
fn no_key() -> Digest {
    use p3_field::PrimeCharacteristicRing;
    [p3_baby_bear::BabyBear::ZERO; 8]
}

fn publics_of(transfer: &Transfer, asset: &Digest) -> TransferPublics {
    TransferPublics::new(
        transfer.input_commitment,
        transfer.nullifier,
        transfer.outputs[0],
        transfer.outputs[1],
        transfer.prev_history,
        *asset,
    )
}

/// Why a hiding transfer was refused.
#[derive(Debug)]
pub enum RefusedHiding {
    Shape(BadShape),
    Proof(Rejected<VerifyError<HidingConfig>>),
}

/// Build and prove one hop with proof-native authorization — **the payment
/// format** (`SPEC.md` §8): spend `input` into `outputs`. Returns the transfer and
/// the proof; there is no `owner_pk` (the note carries none — spec/99
/// `[PROOF-AUTH]`), so the statement is fully determined by the transfer.
///
/// Panics if `keys` are not the input note's keys — that is a caller bug, not an
/// adversarial input. Conservation is NOT checked here: the circuit enforces it,
/// and the negative tests rely on being able to hand this function an inflating
/// pair.
pub fn prove_hiding(
    config: &Vouched<HidingConfig>,
    input: &Note,
    keys: &NoteKeys,
    outputs: [&Note; 2],
    prev_history: &Digest,
) -> (Transfer, HidingAuthProtoProof) {
    assert_eq!(
        input.nullifier_anchor, keys.anchor,
        "keys must be the input note's own"
    );
    let transfer = Transfer {
        input_commitment: input.commitment(),
        nullifier: nullifier::of_note(input, &keys.nullifier_key),
        outputs: vec![outputs[0].commitment(), outputs[1].commitment()],
        prev_history: *prev_history,
    };
    let witness = TransferWitness {
        asset: input.asset,
        input: opening(input, &keys.nullifier_key),
        outputs: [
            opening(outputs[0], &no_key()),
            opening(outputs[1], &no_key()),
        ],
        msg: transfer.bundle_hash(),
    };
    let publics = publics_of(&transfer, &input.asset);
    let proof = prove_authproto_hiding(config, &witness, &publics);
    (transfer, proof)
}

/// Verify one hop — **the consensus entry point**. `asset` is the asset the
/// receiver expects this lineage to carry (checked in-circuit against every note
/// commitment the transfer opens); everything else comes from the transfer
/// itself. The whole statement is bound to the proof by Fiat–Shamir.
pub fn verify_hiding(
    config: &Vouched<HidingConfig>,
    proof: &HidingAuthProtoProof,
    transfer: &Transfer,
    asset: &Digest,
) -> Result<(), RefusedHiding> {
    transfer.check_shape().map_err(RefusedHiding::Shape)?;
    let publics = publics_of(transfer, asset);
    verify_authproto_hiding(config, proof, &publics).map_err(RefusedHiding::Proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crate::history;
    use crate::keys::{derive, WalletSeed};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn asset() -> Digest {
        [BabyBear::from_u32(0xA55E7); 8]
    }

    struct Party {
        keys: NoteKeys,
    }

    fn party(tag: u8, index: u64) -> Party {
        Party {
            keys: derive(&WalletSeed([tag; 32]), index),
        }
    }

    /// **The proof-native money path, end to end with real notes** — the
    /// differential test that pins the AIR's sponge layout, preimage order, and
    /// length/domain tags to `kernel2`'s host types. Authorization is the anchor
    /// preimage; no signature is made, so no key can be used twice. An honest
    /// hop verifies; a transplanted statement (payee or asset swapped) is
    /// refused, which is what the anchor + Fiat–Shamir binding must guarantee.
    #[test]
    fn an_honest_hop_proves_and_verifies() {
        let alice = party(1, 0);
        let bob = party(2, 0);
        let change = party(1, 1);

        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &bob.keys);
        let chg = Note::build(asset(), Amount(40), &change.keys);

        let cfg = uv_air::prove::hiding_config();
        let (transfer, proof) =
            prove_hiding(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        verify_hiding(&cfg, &proof, &transfer, &asset()).expect("honest hop must verify");

        // The statement is bound: a receiver validating a *different* transfer
        // (payee swapped) with this proof must refuse — the bundle hash is in
        // the Fiat–Shamir transcript.
        let mut hijacked = transfer.clone();
        hijacked.outputs[0] = Note::build(asset(), Amount(60), &party(9, 0).keys).commitment();
        assert!(
            verify_hiding(&cfg, &proof, &hijacked, &asset()).is_err(),
            "a proof must not transplant onto a different transfer"
        );
        // Nor under a different asset id.
        assert!(
            verify_hiding(&cfg, &proof, &transfer, &[BabyBear::ONE; 8]).is_err(),
            "a proof must not transplant onto a different asset"
        );
    }

    /// Prove must either panic (debug constraint check) or yield a proof that
    /// does not verify. Silently verifying is the one unacceptable outcome.
    fn must_refuse(
        input: &Note,
        keys: &NoteKeys,
        outputs: [&Note; 2],
        expected_asset: &Digest,
        what: &str,
    ) {
        let cfg = uv_air::prove::hiding_config();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_hiding(&cfg, input, keys, outputs, &history::GENESIS)
        }));
        match attempt {
            Err(_) => {}
            Ok((transfer, proof)) => assert!(
                verify_hiding(&cfg, &proof, &transfer, expected_asset).is_err(),
                "{what} must never verify"
            ),
        }
    }

    /// Conservation: an inflating pair (60 + 50 from 100) must be refused by
    /// the circuit — there is no host-side sum check in front of it.
    #[test]
    fn inflation_is_rejected_by_the_circuit() {
        let alice = party(5, 0);
        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &party(6, 0).keys);
        let too_much_change = Note::build(asset(), Amount(50), &party(5, 1).keys);
        must_refuse(
            &input,
            &alice.keys,
            [&pay, &too_much_change],
            &asset(),
            "an inflating transfer",
        );
    }

    /// Burning is inflation's mirror and equally malformed: 100 -> 60 + 30.
    #[test]
    fn burning_is_rejected_by_the_circuit() {
        let alice = party(7, 0);
        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &party(8, 0).keys);
        let short_change = Note::build(asset(), Amount(30), &party(7, 1).keys);
        must_refuse(
            &input,
            &alice.keys,
            [&pay, &short_change],
            &asset(),
            "a burning transfer",
        );
    }

    /// An output in a different asset must be refused: the circuit absorbs the
    /// SAME public asset into all three commitments, so a mixed-asset transfer's
    /// output commitment cannot open.
    #[test]
    fn an_asset_swap_on_an_output_is_rejected() {
        let alice = party(9, 0);
        let other_asset = [BabyBear::from_u32(0xBAD); 8];
        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(other_asset, Amount(60), &party(10, 0).keys);
        let chg = Note::build(asset(), Amount(40), &party(9, 1).keys);
        must_refuse(
            &input,
            &alice.keys,
            [&pay, &chg],
            &asset(),
            "a mixed-asset transfer",
        );
    }

    /// A one-recipient payment: the second output is a genuine zero-amount note.
    /// Conservation holds (100 = 100 + 0) and the proof verifies.
    #[test]
    fn a_zero_amount_change_note_makes_single_payments_provable() {
        let alice = party(3, 0);
        let bob = party(4, 0);
        let dummy = party(3, 1);

        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(100), &bob.keys);
        let chg = Note::build(asset(), Amount(0), &dummy.keys);

        let cfg = uv_air::prove::hiding_config();
        let (transfer, proof) =
            prove_hiding(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        verify_hiding(&cfg, &proof, &transfer, &asset()).expect("zero-change hop must verify");
    }

    /// A nullifier derived from a foreign key must be refused: the bus ties the
    /// commitment's nullifier_key to the nullifier sponge's input, and the
    /// sponge's output is pinned to the public nullifier.
    #[test]
    fn a_foreign_nullifier_is_rejected() {
        let alice = party(11, 0);
        let mallory = party(12, 0);
        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &party(13, 0).keys);
        let chg = Note::build(asset(), Amount(40), &party(11, 1).keys);

        let cfg = uv_air::prove::hiding_config();
        let (mut transfer, proof) =
            prove_hiding(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        // Present the same proof under a transfer whose nullifier was derived
        // with someone else's key — the message differs, and even a proof
        // freshly bound to this message could not open the input commitment.
        transfer.nullifier =
            nullifier::derive(&mallory.keys.nullifier_key, &transfer.input_commitment);
        assert!(
            verify_hiding(&cfg, &proof, &transfer, &asset()).is_err(),
            "a foreign-key nullifier must never verify"
        );
    }
}
