//! Proving and verifying transfers with real notes — the consensus wrapper.
//!
//! [`verify`] is **the** verification procedure for a hop. It derives the
//! public statement from the [`Transfer`] being validated — the bundle hash
//! above all, which is what makes the proof's WOTS+ digits *this transfer's*
//! digits — then hands off to `uv_air`'s STARK verify, which defines the owner
//! key as `compress(proof.tips)`. Calling the lower layers with a
//! hand-assembled statement proves nothing about any transfer; that is why
//! this module exists.
//!
//! [`prove`] is the sender's side: it builds the transfer from real notes,
//! signs the bundle hash with the input note's one-time key, and lays the
//! witness down for the circuit. The signature happens here and nowhere else —
//! and per spec/02, a wallet must persist the signed payload *before*
//! broadcasting, because replaying the identical payload is the only safe
//! response to a lost record race.

use uv_air::prove::{
    prove_transfer, prove_transfer_hiding, verify_transfer, verify_transfer_hiding, Config,
    HidingConfig, HidingTransferProof, Rejected, TransferProof, TransferPublics, VerifyError,
    Vouched,
};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};
use uv_air::wots::{self, Digest};

use crate::keys::NoteKeys;
use crate::note::Note;
use crate::nullifier;
use crate::transfer::{BadShape, Transfer};

/// Why a transfer was refused before (or by) the proof system.
#[derive(Debug)]
pub enum Refused {
    /// Wrong output count ([`crate::transfer::OUTPUTS`]).
    Shape(BadShape),
    /// The proof itself was rejected.
    Proof(Rejected<VerifyError<Config>>),
}

/// A note's opening for the circuit. `nullifier_key` is the secret whose
/// anchor the note commits to — the spender must supply it, which is exactly
/// what the circuit's anchor row checks. Output notes are built by a payer who
/// does not hold theirs, so they pass a zero placeholder the circuit never
/// reads (only the input's key is constrained).
fn opening(note: &Note, nullifier_key: &Digest) -> NoteOpening {
    NoteOpening {
        amount_limbs: note.amount.limbs(),
        owner_pk: note.owner_pk,
        nullifier_key: *nullifier_key,
        anchor: note.nullifier_anchor,
        randomness: note.randomness,
    }
}

/// Placeholder key for an output opening: the circuit constrains only the
/// input note's anchor preimage.
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

/// Build and prove one hop: spend `input` into `outputs`.
///
/// Panics if `keys` are not the input note's keys — that is a caller bug, not
/// an adversarial input. Conservation is NOT checked here: the circuit
/// enforces it, and the negative tests rely on being able to hand this
/// function an inflating pair.
pub fn prove(
    config: &Vouched<Config>,
    input: &Note,
    keys: &NoteKeys,
    outputs: [&Note; 2],
    prev_history: &Digest,
) -> (Transfer, TransferProof) {
    let perm = wots::permutation();
    assert_eq!(
        input.owner_pk,
        wots::public_key(&perm, &keys.wots_seed),
        "keys must be the input note's own"
    );
    assert_eq!(input.nullifier_anchor, keys.anchor);

    let transfer = Transfer {
        input_commitment: input.commitment(),
        nullifier: nullifier::of_note(input, &keys.nullifier_key),
        outputs: vec![outputs[0].commitment(), outputs[1].commitment()],
        prev_history: *prev_history,
    };
    let msg = transfer.bundle_hash();
    let sig = wots::sign(&perm, &keys.wots_seed, &msg);

    let witness = TransferWitness {
        asset: input.asset,
        input: opening(input, &keys.nullifier_key),
        outputs: [
            opening(outputs[0], &no_key()),
            opening(outputs[1], &no_key()),
        ],
        msg,
        sig,
    };
    let publics = publics_of(&transfer, &input.asset);
    let proof = prove_transfer(config, &witness, &publics);
    (transfer, proof)
}

/// Verify one hop: the consensus entry point.
///
/// `asset` is the asset the receiver expects this lineage to carry (checked
/// in-circuit against every note commitment the transfer opens). Everything
/// else comes from the transfer itself.
pub fn verify(
    config: &Vouched<Config>,
    proof: &TransferProof,
    transfer: &Transfer,
    asset: &Digest,
) -> Result<(), Refused> {
    transfer.check_shape().map_err(Refused::Shape)?;
    let publics = publics_of(transfer, asset);
    verify_transfer(config, proof, &publics).map_err(Refused::Proof)
}

/// Why a hiding transfer was refused.
#[derive(Debug)]
pub enum RefusedHiding {
    Shape(BadShape),
    Proof(Rejected<VerifyError<HidingConfig>>),
}

/// [`prove`], zero-knowledge configuration — **the payment format** (spec/04):
/// the witness contains amounts, keys, and randomness, and the hiding STARK is
/// what keeps them from every later holder of the lineage.
pub fn prove_hiding(
    config: &Vouched<HidingConfig>,
    input: &Note,
    keys: &NoteKeys,
    outputs: [&Note; 2],
    prev_history: &Digest,
) -> (Transfer, HidingTransferProof) {
    let perm = wots::permutation();
    assert_eq!(
        input.owner_pk,
        wots::public_key(&perm, &keys.wots_seed),
        "keys must be the input note's own"
    );
    assert_eq!(input.nullifier_anchor, keys.anchor);

    let transfer = Transfer {
        input_commitment: input.commitment(),
        nullifier: nullifier::of_note(input, &keys.nullifier_key),
        outputs: vec![outputs[0].commitment(), outputs[1].commitment()],
        prev_history: *prev_history,
    };
    let msg = transfer.bundle_hash();
    let sig = wots::sign(&perm, &keys.wots_seed, &msg);
    let witness = TransferWitness {
        asset: input.asset,
        input: opening(input, &keys.nullifier_key),
        outputs: [
            opening(outputs[0], &no_key()),
            opening(outputs[1], &no_key()),
        ],
        msg,
        sig,
    };
    let publics = publics_of(&transfer, &input.asset);
    let proof = prove_transfer_hiding(config, &witness, &publics);
    (transfer, proof)
}

/// [`verify`], zero-knowledge configuration.
pub fn verify_hiding(
    config: &Vouched<HidingConfig>,
    proof: &HidingTransferProof,
    transfer: &Transfer,
    asset: &Digest,
) -> Result<(), RefusedHiding> {
    transfer.check_shape().map_err(RefusedHiding::Shape)?;
    let publics = publics_of(transfer, asset);
    verify_transfer_hiding(config, proof, &publics).map_err(RefusedHiding::Proof)
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

    /// The whole hop, proven and verified end to end with real notes — the
    /// circuit accepting exactly what `kernel2`'s host types produce. This is
    /// the differential test that pins the AIR's sponge layout, preimage
    /// order, and length/domain tags to the host implementation: any drift
    /// makes this proof fail, loudly.
    #[test]
    fn an_honest_hop_proves_and_verifies() {
        let alice = party(1, 0);
        let bob = party(2, 0);
        let change = party(1, 1);

        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &bob.keys);
        let chg = Note::build(asset(), Amount(40), &change.keys);

        let cfg = uv_air::prove::config();
        let (transfer, proof) = prove(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        verify(&cfg, &proof, &transfer, &asset()).expect("honest hop must verify");

        // And the statement is bound: a receiver validating a *different*
        // transfer (payee swapped) with this proof must refuse.
        let mut hijacked = transfer.clone();
        hijacked.outputs[0] = Note::build(asset(), Amount(60), &party(9, 0).keys).commitment();
        assert!(
            verify(&cfg, &proof, &hijacked, &asset()).is_err(),
            "a proof must not transplant onto a different transfer"
        );
        // Nor under a different asset id.
        assert!(
            verify(&cfg, &proof, &transfer, &[BabyBear::ONE; 8]).is_err(),
            "a proof must not transplant onto a different asset"
        );
    }

    /// A one-recipient payment: the second output is a genuine zero-amount
    /// note. Conservation holds (100 = 100 + 0) and the proof verifies.
    #[test]
    fn a_zero_amount_change_note_makes_single_payments_provable() {
        let alice = party(3, 0);
        let bob = party(4, 0);
        let dummy = party(3, 1);

        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(100), &bob.keys);
        let chg = Note::build(asset(), Amount(0), &dummy.keys);

        let cfg = uv_air::prove::config();
        let (transfer, proof) = prove(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        verify(&cfg, &proof, &transfer, &asset()).expect("zero-change hop must verify");
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
        let cfg = uv_air::prove::config();
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove(&cfg, input, keys, outputs, &history::GENESIS)
        }));
        match attempt {
            Err(_) => {}
            Ok((transfer, proof)) => assert!(
                verify(&cfg, &proof, &transfer, expected_asset).is_err(),
                "{what} must never verify"
            ),
        }
    }

    /// Conservation: an inflating pair (60 + 50 from 100) must be refused by
    /// constraint 28 — there is no host-side sum check standing in front of
    /// it, deliberately.
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

    /// An output in a different asset must be refused: the circuit absorbs
    /// the SAME public asset into all three commitments (constraint 23), so a
    /// mixed-asset transfer's output commitment cannot open.
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

    /// A nullifier derived from a foreign key must be refused: the bus ties
    /// the commitment's nullifier_key to the nullifier sponge's input, and
    /// the sponge's output is pinned to the public nullifier.
    #[test]
    fn a_foreign_nullifier_is_rejected() {
        let alice = party(11, 0);
        let mallory = party(12, 0);
        let input = Note::build(asset(), Amount(100), &alice.keys);
        let pay = Note::build(asset(), Amount(60), &party(13, 0).keys);
        let chg = Note::build(asset(), Amount(40), &party(11, 1).keys);

        let cfg = uv_air::prove::config();
        let (mut transfer, proof) =
            prove(&cfg, &input, &alice.keys, [&pay, &chg], &history::GENESIS);
        // Present the same proof under a transfer whose nullifier was derived
        // with someone else's key — the message differs, and even a proof
        // freshly bound to this message could not open the input commitment.
        transfer.nullifier =
            nullifier::derive(&mallory.keys.nullifier_key, &transfer.input_commitment);
        assert!(
            verify(&cfg, &proof, &transfer, &asset()).is_err(),
            "a foreign-key nullifier must never verify"
        );
    }
}
