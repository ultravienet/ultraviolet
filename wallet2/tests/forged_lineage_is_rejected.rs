//! Regression test: the whole rail, against a note forged from nothing.
//!
//! **This attack worked.** `p3_uni_stark` takes the trace height from the proof
//! and never pins it, and the transfer AIR is only sound at its designed height.
//! At eight rows the sponge section never begins, so the commitment openings,
//! the nullifier derivation, conservation and the spend anchor are all gated off
//! — and every public value the verifier carefully builds is read by nothing.
//!
//! Mallory holds no key, no seed and no anchor preimage. She spends the asset's
//! public genesis commitment, invents a nullifier, pays herself more than the
//! entire issuance, and publishes the record. Before the fix, every host-side
//! check downstream passed, because all of them sit behind a proof that proved
//! nothing.
//!
//! This is kept running because it is the only test here written by an
//! adversary rather than by the author of the thing it attacks. The fix is
//! `uv_air::prove::check_height`.

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_RC16_EXTERNAL_FINAL,
    BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, RoundConstants};
use p3_uni_stark::prove as p3_prove;

use uv_air::prove::{hiding_config, HidingTransferProof, TransferPublics};
use uv_air::transfer_air::{TransferAir, NUM_COLS};
use uv_air::wots::{self, Digest, CHAINS, LOG_W, WIDTH};
use uv_air::wots_air::{
    BITS, DIGIT, HALF_FULL_ROUNDS, OH, P2_COLS, PARTIAL_ROUNDS, PINV, POS, ROWS_PER_CHAIN,
    SBOX_DEGREE, SBOX_REGISTERS,
};
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer::Transfer;
use uv_wallet2::accept::{accept, Hop, Lineage};
use uv_wallet2::chain::{Chain, MockChain};

/// A trace satisfying every `TransferAir` constraint while proving nothing.
fn vacuous_trace(height: usize, digit0: u8) -> RowMajorMatrix<BabyBear> {
    assert!(height < ROWS_PER_CHAIN, "must never reach pos = W-2");
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
        dst[DIGIT] = BabyBear::from_u32(u32::from(digit0));
        for k in 0..LOG_W {
            dst[BITS + k] = BabyBear::from_bool((digit0 >> k) & 1 == 1);
        }
        dst[OH] = BabyBear::ONE;
        dst[POS] = BabyBear::from_u32(row as u32);
        dst[PINV] = (BabyBear::from_u32(row as u32)
            - BabyBear::from_u32((ROWS_PER_CHAIN - 1) as u32))
        .inverse();
    }
    RowMajorMatrix::new(values, NUM_COLS)
}

#[test]
fn a_forged_lineage_cannot_mint_money() {
    let asset = [BabyBear::from_u32(0xC0117); 8];
    let cfg = hiding_config();

    // The asset's trusted issuance anchor — public, known to every receiver.
    let issuer = derive(&WalletSeed([1u8; 32]), 0);
    let genesis = Note::build(asset, Amount(10_000), &issuer);
    let genesis_commitment = genesis.commitment();

    // Mallory holds nothing but her own fresh keys.
    let mallory = derive(&WalletSeed([66u8; 32]), 0);
    let m_dummy = derive(&WalletSeed([66u8; 32]), 1);
    let stolen = Note::build(asset, Amount(1_000_000_000), &mallory); // > genesis
    let dummy = Note::build(asset, Amount(0), &m_dummy);

    let transfer = Transfer {
        input_commitment: genesis_commitment,
        nullifier: [BabyBear::from_u32(0xBADBAD); 8], // invented; no key needed
        outputs: vec![stolen.commitment(), dummy.commitment()],
        prev_history: history::GENESIS,
    };

    let publics = TransferPublics::new(
        transfer.input_commitment,
        transfer.nullifier,
        transfer.outputs[0],
        transfer.outputs[1],
        transfer.prev_history,
        asset,
    );
    // The tips ride with the proof; the host *defines* owner_pk from them, and
    // nothing constrains them at this height.
    let tips: [Digest; CHAINS] = core::array::from_fn(|c| [BabyBear::from_u32(c as u32 + 1); 8]);
    let pv = publics.to_public_values(&tips);

    let trace = vacuous_trace(8, wots::digits(publics.msg())[0]);
    let stark = p3_prove(cfg.inner(), &TransferAir::default(), trace, &pv);
    let proof = HidingTransferProof {
        stark,
        tips: tips.to_vec(),
    };

    // Publish the record and let it confirm.
    let mut chain = MockChain::new();
    chain.mine(10);
    chain
        .publish(&Record {
            nullifier: transfer.nullifier,
            bundle_hash: transfer.bundle_hash(),
        })
        .unwrap();
    chain.mine(10);

    let lineage: Lineage = vec![Hop {
        transfer,
        proof: bincode::serialize(&proof).unwrap(),
    }];

    let verdict = accept(
        &cfg,
        &chain,
        &asset,
        &genesis_commitment,
        &stolen,
        &lineage,
        None,
    );
    assert!(
        verdict.is_err(),
        "MINT ACCEPTED: wallet2::accept took a note forged from nothing — {verdict:?}"
    );
}
