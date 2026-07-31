//! Claim S6: **a proof cannot be transplanted to a different transfer.**
//!
//! This is a theft claim, not a hygiene one. If a proof of "spend note A to pay
//! Bob" also verifies against the statement "spend note A to pay Mallory", then
//! anyone who has ever seen a valid payment can redirect it, and no key was
//! needed to do it. Under proof-native authorization the proof *is* the
//! authorization (SPEC.md §8.4), so a statement the proof does not bind is a
//! statement anyone may choose.
//!
//! The mechanism is Fiat–Shamir: the transcript absorbs **all 56 public values**
//! before any challenge is drawn, so a proof commits to the entire statement and
//! not merely to the parts a constraint happens to read.
//!
//! ## Why this test is exhaustive rather than illustrative
//!
//! S6 sat as **test-only** in `formal/CLAIMS.md` with `air/src/prove.rs` and a
//! vague "`authproto_air.rs` test" as its evidence — and on 2026-07-30 a check of
//! that claim found **no test perturbed a public value at all.** The gap was in
//! the matrix's Code column, which is exactly what the matrix exists to expose.
//!
//! The domain here is closed and small: a statement is 56 field elements. So this
//! does not pick a representative one to tamper with — it tampers with **every
//! position, one at a time**, and requires refusal each time. There is nowhere
//! for an unbound value to hide, because there is no position left unvisited.
//!
//! Two things are deliberately *not* claimed. This says nothing about the
//! soundness of Fiat–Shamir itself, which is an assumption (`AUDIT-BRIEF.md`
//! names the transcript as review surface). And a refusal here can come from a
//! constraint reading the value directly rather than from transcript binding —
//! the claim is that no altered statement verifies, which is the property that
//! keeps money safe, not a claim about which mechanism did the refusing.

use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove as p3_prove, verify as p3_verify};

use uv_air::authproto_air::{AuthProtoAir, NUM_PUBLIC_VALUES};
use uv_air::poseidon2::Digest;
use uv_air::prove::{self, TransferPublics};
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

/// One honest hop, built the way every other test in this crate builds it.
fn honest() -> (TransferWitness, Vec<BabyBear>) {
    let limbs = |v: u64| -> [BabyBear; 4] {
        core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
    };
    let open = |tag: u32, v: u64| -> NoteOpening {
        let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
        NoteOpening {
            amount_limbs: limbs(v),
            anchor: sponge::hash(Domain::SpendAnchor, &nk),
            nullifier_key: nk,
            randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
        }
    };
    let commitment = |o: &NoteOpening, asset: &Digest| {
        let mut p = Vec::new();
        p.extend_from_slice(asset);
        p.extend_from_slice(&o.amount_limbs);
        p.extend_from_slice(&o.anchor);
        p.extend_from_slice(&o.randomness);
        sponge::hash(Domain::Note, &p)
    };

    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = open(41, 100);
    let outs = [open(42, 60), open(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);
    let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
    let out0 = commitment(&outs[0], &asset);
    let out1 = commitment(&outs[1], &asset);
    let prev_history = [BabyBear::ZERO; 8];
    let publics =
        TransferPublics::new(input_commitment, nullifier, out0, out1, prev_history, asset);
    let msg = *publics.msg();

    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    for part in [
        &input_commitment,
        &nullifier,
        &out0,
        &out1,
        &prev_history,
        &asset,
        &msg,
    ] {
        pv.extend_from_slice(part);
    }
    assert_eq!(pv.len(), NUM_PUBLIC_VALUES);

    (
        TransferWitness {
            asset,
            input,
            outputs: outs,
            msg,
        },
        pv,
    )
}

/// Which of the seven digests position `i` belongs to — for a failure message
/// that names the hole instead of printing an index.
fn field_name(i: usize) -> &'static str {
    match i / 8 {
        0 => "input_commitment",
        1 => "nullifier",
        2 => "out0",
        3 => "out1",
        4 => "prev_history",
        5 => "asset",
        _ => "msg (the bundle hash — the payee's identity)",
    }
}

/// **Every one of the 56 public values is bound.** Prove once, honestly; then
/// verify that proof against 56 statements each differing in one element.
#[test]
fn no_altered_statement_verifies_against_an_honest_proof() {
    let (w, pv) = honest();
    let cfg = prove::config();
    let air = AuthProtoAir::default();

    // The control. Without it a broken verifier that refuses everything would
    // pass every assertion below and read as perfect binding.
    let proof = p3_prove(cfg.inner(), &air, uv_air::authproto_air::generate(&w), &pv);
    assert!(
        p3_verify(cfg.inner(), &air, &proof, &pv).is_ok(),
        "control: the honest statement must verify, or the test below proves nothing"
    );

    let mut accepted_forgeries = Vec::new();
    let mut attempted = 0usize;
    for i in 0..NUM_PUBLIC_VALUES {
        // Two perturbations per position, because one is not enough: `+1` moves
        // by a unit and could conceivably be absorbed by an arithmetic
        // relationship, while zeroing removes the value entirely — the shape a
        // transplant to an all-zero or defaulted statement takes.
        for (label, altered) in [("+1", pv[i] + BabyBear::ONE), ("zeroed", BabyBear::ZERO)] {
            if altered == pv[i] {
                continue; // zeroing an already-zero element alters nothing
            }
            let mut forged = pv.clone();
            forged[i] = altered;
            attempted += 1;
            let verified = catch_unwind(AssertUnwindSafe(|| {
                p3_verify(cfg.inner(), &air, &proof, &forged).is_ok()
            }))
            .unwrap_or(false); // a panic is a refusal, not an acceptance
            if verified {
                accepted_forgeries.push(format!(
                    "public value {i} ({}, {label}) is NOT bound",
                    field_name(i)
                ));
            }
        }
    }

    // `prev_history` is all zeros in this witness, so its 8 positions skip the
    // "zeroed" variant: 56 × 2 − 8 = 104. Asserted exactly, because the `continue`
    // above is the kind of line that can quietly hollow a loop out — and a test
    // that made zero attempts would report perfect binding.
    assert_eq!(
        attempted, 104,
        "the forgery loop must actually attempt every position; a skipped loop \
         passes vacuously"
    );

    assert!(
        accepted_forgeries.is_empty(),
        "an honest proof verified against an altered statement, so a proof can be \
         transplanted and a payment redirected without any key (claim S6):\n  {}",
        accepted_forgeries.join("\n  ")
    );
}

/// The transplant said in the language of the attack: a proof built to pay one
/// payee must not verify as a payment to a different one.
///
/// `msg` is the bundle hash, which is where the payee's slot and the amount they
/// were promised live. This is the same property the loop above covers for
/// positions 48..56, kept separate because a reader looking for "can my payment
/// be redirected?" should find it stated in those words rather than as an index
/// range.
#[test]
fn a_proof_for_one_payee_does_not_verify_for_another() {
    let (w, pv) = honest();
    let cfg = prove::config();
    let air = AuthProtoAir::default();
    let proof = p3_prove(cfg.inner(), &air, uv_air::authproto_air::generate(&w), &pv);
    assert!(p3_verify(cfg.inner(), &air, &proof, &pv).is_ok(), "control");

    // Mallory rewrites the bundle hash to a bundle of her own choosing and
    // keeps the honest proof, the honest nullifier, and the honest outputs.
    let mut redirected = pv.clone();
    for slot in redirected.iter_mut().skip(48).take(8) {
        *slot = BabyBear::from_u32(0xDEAD);
    }
    assert_ne!(
        redirected, pv,
        "the redirect must actually change something"
    );

    let verified = catch_unwind(AssertUnwindSafe(|| {
        p3_verify(cfg.inner(), &air, &proof, &redirected).is_ok()
    }))
    .unwrap_or(false);
    assert!(
        !verified,
        "a proof of a payment to one payee verified as a payment to another: \
         anyone who has seen a valid payment could redirect it"
    );
}
