//! The hiding proof must be randomized. This is a regression test for a real bug.
//!
//! FRI opens trace cells at its query positions, and those cells hold witness
//! data. The blinding masks them, so the mask must be secret from everyone but
//! the prover. It used to be seeded from a compile-time constant, which meant
//! any reader of the source could regenerate the mask and subtract it off — and
//! meant proving the same payment twice produced byte-identical proofs, a
//! fingerprint of the witness.
//!
//! Byte-equality across two proofs of one witness is therefore the alarm. It
//! fires on a fixed seed, on a seed derived from anything predictable, and on
//! blinding accidentally disabled.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use uv_air::prove;
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

fn limbs(v: u64) -> [BabyBear; 4] {
    core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
}

fn opening(tag: u32, v: u64) -> NoteOpening {
    let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
    NoteOpening {
        amount_limbs: limbs(v),
        anchor: sponge::hash(Domain::SpendAnchor, &nk),
        nullifier_key: nk,
        randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
    }
}

fn commitment(o: &NoteOpening, asset: &[BabyBear; 8]) -> [BabyBear; 8] {
    let mut p = Vec::new();
    p.extend_from_slice(asset);
    p.extend_from_slice(&o.amount_limbs);
    p.extend_from_slice(&o.anchor);
    p.extend_from_slice(&o.randomness);
    sponge::hash(Domain::Note, &p)
}

fn case(amount: u64) -> (TransferWitness, prove::TransferPublics) {
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(41, amount);
    let outs = [opening(42, amount - 40), opening(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);
    let publics = prove::TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    let msg = *publics.msg();
    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };
    (witness, publics)
}

/// Two proofs of the *same* payment must not be the same bytes.
#[test]
fn the_same_payment_never_proves_to_the_same_bytes_twice() {
    let (w, p) = case(100);
    // Exactly what `uv send` does: build a config, prove once, in a fresh process.
    let a = bincode::serialize(&prove::prove_authproto_hiding(
        &prove::hiding_config(),
        &w,
        &p,
    ))
    .unwrap();
    let b = bincode::serialize(&prove::prove_authproto_hiding(
        &prove::hiding_config(),
        &w,
        &p,
    ))
    .unwrap();
    assert_eq!(a.len(), b.len(), "proof size should not depend on blinding");
    assert_ne!(
        a, b,
        "the hiding proof is a deterministic function of its witness — \
         the blinding is fixed, predictable, or absent"
    );
}

/// ...and both still verify. Randomized blinding must not cost correctness.
#[test]
fn randomized_blinding_still_verifies() {
    let (w, p) = case(100);
    for _ in 0..2 {
        let proof = prove::prove_authproto_hiding(&prove::hiding_config(), &w, &p);
        prove::verify_authproto_hiding(&prove::hiding_config(), &proof, &p)
            .expect("a freshly blinded proof must verify");
    }
}
