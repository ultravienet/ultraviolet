//! Regression test for a total soundness break: a prover-chosen trace height.
//!
//! **This forgery worked.** It is kept, running, because the class is subtle and
//! a future refactor could reopen it.
//!
//! `p3_uni_stark::verify` reads `degree_bits` out of the proof
//! (p3-uni-stark-0.4.3/src/verifier.rs:218-222) and never compares it to
//! anything. Nothing in `uv_air::prove::verify_transfer` or
//! `uv_kernel2::transfer_prove::verify` pins it either. `TransferAir` is only
//! sound at height 1024: at height 8 the position cycle never reaches W-2, so
//! `is_last` is never forced, no tip is bound (constraint 17), the SP register
//! stays zero, and every sponge constraint (20-32) is gated off. Every
//! transfer-specific public value is then unconstrained.
//!
//! This test forges a proof for a transfer of the attacker's choosing and feeds
//! it to the exact public values `uv_kernel2::transfer_prove::verify` builds.
//! The fix is `prove::check_height`: the height an AIR is sound at is part of
//! the statement, so the verifier pins it and rejects everything else.

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_RC16_EXTERNAL_FINAL,
    BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, RoundConstants};
use p3_uni_stark::prove as p3_prove;

use uv_air::prove::{config, verify_transfer, TransferProof, TransferPublics};
use uv_air::transfer_air::{TransferAir, NUM_COLS};
use uv_air::wots::{self, Digest, CHAINS, LOG_W, WIDTH};
use uv_air::wots_air::{
    ACC, BITS, CHAIN_IN, CHAIN_OUT, DIGIT, HALF_FULL_ROUNDS, IS_LAST, OH, P2_COLS, PARTIAL_ROUNDS,
    PINV, POS, ROWS_PER_CHAIN, SBOX_DEGREE, SBOX_REGISTERS, SEL,
};

fn d(tag: u32) -> Digest {
    [BabyBear::from_u32(tag); 8]
}

/// A trace of `height` rows that satisfies every `TransferAir` constraint while
/// proving nothing: one partial chain, all selectors off, no sponge section.
fn vacuous_trace(height: usize, digit0: u8) -> RowMajorMatrix<BabyBear> {
    assert!(
        height < ROWS_PER_CHAIN,
        "must not reach the pos = W-2 boundary"
    );

    // Every row permutes the all-zero state, which is exactly the shape
    // constraint 3 demands of a non-sponge row: [chain_in | zeros] with
    // chain_in = 0.
    let states = vec![[BabyBear::ZERO; WIDTH]; height];
    let p2 = generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(
        states,
        &RoundConstants::new(
            BABYBEAR_RC16_EXTERNAL_INITIAL,
            BABYBEAR_RC16_INTERNAL,
            BABYBEAR_RC16_EXTERNAL_FINAL,
        ),
        0,
    );

    let mut values = vec![BabyBear::ZERO; height * NUM_COLS];
    for row in 0..height {
        let dst = &mut values[row * NUM_COLS..(row + 1) * NUM_COLS];
        dst[..P2_COLS].copy_from_slice(&p2.values[row * P2_COLS..(row + 1) * P2_COLS]);
        // chain_in = chain_out = 0, sel = is_last = acc = 0 (already zero).
        let _ = (CHAIN_IN, CHAIN_OUT, SEL, IS_LAST, ACC);
        // Constraint 16 pins the digit of chain 0 — the only thing this trace
        // is forced to agree with the message about.
        dst[DIGIT] = BabyBear::from_u32(u32::from(digit0));
        for k in 0..LOG_W {
            dst[BITS + k] = BabyBear::from_bool((digit0 >> k) & 1 == 1);
        }
        dst[OH] = BabyBear::ONE; // chain 0, never rotated (is_last is never 1)
        dst[POS] = BabyBear::from_u32(row as u32);
        // Constraint 14: (pos - (W-2)) * pinv = 1 - is_last = 1.
        dst[PINV] = (BabyBear::from_u32(row as u32)
            - BabyBear::from_u32((ROWS_PER_CHAIN - 1) as u32))
        .inverse();
        // SP, NK, T, AMT_*, CARRY, RBITS all stay zero: the sponge section
        // simply does not exist, and every constraint that reads it is gated
        // on the SP register.
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[test]
fn a_short_trace_cannot_forge_a_transfer() {
    // The attacker's transfer: spend a commitment they do not own, pay
    // themselves, in whatever asset the receiver is expecting.
    let victims_note = d(0xDEAD);
    let asset = d(0xA55E7);
    let attacker_out0 = d(0x1111);
    let attacker_out1 = d(0x2222);
    let nullifier = d(0x3333); // any value at all
    let prev_history = [BabyBear::ZERO; 8]; // kernel2::history::GENESIS

    let publics = TransferPublics::new(
        victims_note,
        nullifier,
        attacker_out0,
        attacker_out1,
        prev_history,
        asset,
    );
    let msg = *publics.msg();

    // The tips ride with the proof and the host *defines* owner_pk from them.
    // Nothing constrains them at this height, so garbage will do.
    let tips: [Digest; CHAINS] = core::array::from_fn(|c| d(0x5000 + c as u32));

    let pv = publics.to_public_values(&tips);
    let digit0 = wots::digits(&msg)[0];

    let cfg = config();
    let air = TransferAir::default();
    let trace = vacuous_trace(8, digit0);
    let stark = p3_prove(cfg.inner(), &air, trace, &pv);
    let proof = TransferProof {
        stark,
        tips: tips.to_vec(),
    };

    // This is precisely what `uv_kernel2::transfer_prove::verify` does after
    // `check_shape` (which a 2-output transfer passes).
    let verdict = verify_transfer(&cfg, &proof, &publics);
    assert!(
        matches!(
            verdict,
            Err(uv_air::prove::Rejected::WrongTraceHeight { .. })
        ),
        "FORGERY ACCEPTED: a short trace proved an arbitrary transfer — got {verdict:?}"
    );
}

/// The same hole in the signature AIR, which shares constraints 1-17.
#[test]
fn a_short_trace_cannot_forge_a_signature_either() {
    use uv_air::prove::{verify, WotsProof};
    use uv_air::wots_air::WotsAir;

    let msg = d(0xBEEF);
    let tips: [Digest; CHAINS] = core::array::from_fn(|c| d(0x7000 + c as u32));
    let perm = wots::permutation();
    let pk = wots::compress(&perm, &tips);

    let mut pv: Vec<BabyBear> = wots::digits(&msg)
        .iter()
        .map(|&x| BabyBear::from_u32(u32::from(x)))
        .collect();
    for tip in &tips {
        pv.extend_from_slice(tip);
    }

    let cfg = config();
    let trace = vacuous_trace(8, wots::digits(&msg)[0]);
    let stark = p3_prove(cfg.inner(), &WotsAir::default(), trace, &pv);
    let proof = WotsProof {
        stark,
        tips: tips.to_vec(),
    };

    let verdict = verify(&cfg, &proof, &msg, &pk);
    assert!(
        matches!(
            verdict,
            Err(uv_air::prove::Rejected::WrongTraceHeight { .. })
        ),
        "FORGERY ACCEPTED: a short trace forged a signature — got {verdict:?}"
    );
}
