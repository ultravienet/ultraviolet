//! **The transfer circuit: proof-native authorization, no signature.**
//!
//! This is *the* money-path circuit (spec/99 `[PROOF-AUTH]`, since 2026-07-29).
//! It began as a measurement prototype named for its comparison against the
//! WOTS+ signature circuit; that circuit measured 6.7× slower and was deleted,
//! and this became the consensus circuit. The file keeps the name.
//!
//! ## What it proves
//!
//! A spender must exhibit, in-circuit, a hash preimage of the anchor the note
//! committed to (constraint 12, = production 32). That *is* authorization —
//! knowledge of a secret only the payee holds, bound to this exact transfer
//! because every public value (the bundle hash included) enters the Fiat–Shamir
//! transcript. There is no signature beside it: the WOTS+ chains that once
//! occupied 1,005 of 1,024 rows are gone, and trace height is 16.
//!
//! Removing the signature removed the system's sharpest operational hazard —
//! signing twice under one key discloses the key, the reason a sign-log,
//! replay-instead-of-resign, and fund-critical slot reservations existed.
//! Proving twice reveals nothing.
//!
//! ## The cost, stated plainly
//!
//! The witness — the nullifier key — enters every spend proof, so witness
//! secrecy (zero-knowledge) is load-bearing for **funds**, not just privacy:
//! the hiding configuration is the only configuration on the money path. Anchors
//! stay one-time per note, so a leak's blast radius is one note. The assumption
//! base is unchanged — FRI and Poseidon2 are hashes — and the Fiat–Shamir
//! binding of proof to statement is already load-bearing.
//!
//! ## The note preimage, and why it is 28 elements
//!
//! A note commits to `asset ‖ amount(4) ‖ anchor ‖ rnd` = 28 field elements —
//! **no `owner_pk`**. The one-time public key that lived here authorized nothing
//! (the anchor preimage does) and only cost sponge rows, so it was dropped when
//! the signature left the money path. A note sponge is now four absorb rows, and
//! a whole transfer's five sponges fit in 15 rows / a 16-row trace.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::Poseidon2Cols;

use crate::poseidon2_eval::{
    constants, eval_permutation, Constants, HALF_FULL_ROUNDS, P2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE,
    SBOX_REGISTERS,
};
use crate::sponge::{
    Domain, AMOUNT_LIMBS, ANCHOR_PREIMAGE, NF_PREIMAGE, NOTE_PREIMAGE, SPONGE_ROWS,
};
use crate::transfer_trace::TransferWitness;
use crate::wots::{N, WIDTH};

// ---- Column layout: the Poseidon2 permutation, then the sponge registers ----
pub const SP: usize = P2_COLS;
pub const NK: usize = SP + SPONGE_ROWS;
pub const T: usize = NK + N;
pub const AMT_IN: usize = T + N;
pub const AMT_O0: usize = AMT_IN + AMOUNT_LIMBS;
pub const AMT_O1: usize = AMT_O0 + AMOUNT_LIMBS;
pub const CARRY: usize = AMT_O1 + AMOUNT_LIMBS;
pub const RBITS: usize = CARRY + 3;
pub const NUM_COLS: usize = RBITS + 16;

// ---- Public values ----
//
// No tips and no per-digit binding: the statement is bound to the proof by
// Fiat–Shamir over ALL public values, exactly the mechanism that already binds
// `PV_PREV_HISTORY`. There is **no `owner_pk`** — it was dropped from the note
// (spec/99 `[PROOF-AUTH]`), so it is neither committed nor public.
pub const PV_INPUT_COMMITMENT: usize = 0;
pub const PV_NULLIFIER: usize = PV_INPUT_COMMITMENT + N;
pub const PV_OUT0: usize = PV_NULLIFIER + N;
pub const PV_OUT1: usize = PV_OUT0 + N;
pub const PV_PREV_HISTORY: usize = PV_OUT1 + N;
pub const PV_ASSET: usize = PV_PREV_HISTORY + N;
/// The bundle hash. Not read by any constraint; bound by Fiat–Shamir, which is
/// what makes the proof a signature of knowledge over *this* transfer.
pub const PV_MSG: usize = PV_ASSET + N;
pub const NUM_PUBLIC_VALUES: usize = PV_MSG + N;

/// Trace height: the 15 sponge rows, padded to a power of two.
pub const HEIGHT: usize = SPONGE_ROWS.next_power_of_two();

// Sponge tiling. A note commitment is now 28 elements = 4 absorb rows (was 5):
// C_in at 0–3, nullifier at 4–5, C_out0 at 6–9, C_out1 at 10–13, anchor at 14.
const STARTS: [usize; 5] = [0, 4, 6, 10, 14];
const ANCHOR_ROW: usize = 14;
const PINS: [(usize, usize); 4] = [
    (3, PV_INPUT_COMMITMENT),
    (5, PV_NULLIFIER),
    (9, PV_OUT0),
    (13, PV_OUT1),
];

pub struct AuthProtoAir {
    constants: Constants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
}

impl Default for AuthProtoAir {
    fn default() -> Self {
        AuthProtoAir {
            constants: constants(),
        }
    }
}

impl<F> BaseAir<F> for AuthProtoAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

type P2<'a, AB> = &'a Poseidon2Cols<
    <AB as AirBuilder>::Var,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

impl<AB: AirBuilderWithPublicValues<F = BabyBear>> Air<AB> for AuthProtoAir {
    fn eval(&self, builder: &mut AB) {
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&x| x.into()).collect();
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("empty trace");
        let p2_local: P2<AB> = local[..P2_COLS].borrow();
        let p2_next: P2<AB> = next[..P2_COLS].borrow();
        let perm_out = &p2_local.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        let sp = |row: &[AB::Var], j: usize| -> AB::Expr { row[SP + j].clone().into() };

        // 1. The permutation itself, every row — identical machinery to
        //     production constraint 1.
        eval_permutation::<
            AB,
            GenericPoseidon2LinearLayersBabyBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(&self.constants, builder, p2_local);

        // 2. The upstream `export` flag is pinned, as in production: a column
        //      nothing reads is a column a prover controls.
        builder.assert_zero(local[0].clone().into() - AB::Expr::ONE);

        // 3. SP seeding. Production seeds the section off the last chain row;
        //     there are no chains here, so the section starts at row 0. The
        //     register is still fully determined by induction: row 0 is
        //     exactly (1, 0, …, 0), and every transition shifts by one with a
        //     zero fed in.
        builder
            .when_first_row()
            .assert_zero(local[SP].clone().into() - AB::Expr::ONE);
        for j in 1..SPONGE_ROWS {
            builder.when_first_row().assert_zero(local[SP + j].clone());
        }
        {
            let mut when = builder.when_transition();
            when.assert_zero(sp(&next, 0));
            for j in 1..SPONGE_ROWS {
                when.assert_zero(sp(&next, j) - sp(&local, j - 1));
            }
        }

        let is_sponge: AB::Expr = (0..SPONGE_ROWS)
            .map(|j| sp(&local, j))
            .fold(AB::Expr::ZERO, |a, b| a + b);

        // 4. Padding rows feed the permutation nothing. Production's chain
        //     wiring pins non-sponge inputs; without chains the padding rows
        //     would otherwise be 16 free lanes per row.
        for i in 0..WIDTH {
            builder.assert_zero(
                (AB::Expr::ONE - is_sponge.clone()) * p2_local.inputs[i].clone().into(),
            );
        }

        let start: AB::Expr = STARTS
            .iter()
            .map(|&j| sp(&local, j))
            .fold(AB::Expr::ZERO, |a, b| a + b);
        let note_start = sp(&local, 0) + sp(&local, 6) + sp(&local, 10);
        let null_start = sp(&local, 4);
        let anchor_start = sp(&local, ANCHOR_ROW);

        // 5. (production 20) A sponge starts with a zeroed capacity.
        for i in N..WIDTH - 2 {
            builder.assert_zero(start.clone() * p2_local.inputs[i].clone().into());
        }

        // 6. (production 21) Input length in lane 14.
        builder.assert_zero(
            note_start.clone()
                * (p2_local.inputs[WIDTH - 2].clone().into()
                    - AB::Expr::from_u64(NOTE_PREIMAGE as u64))
                + null_start.clone()
                    * (p2_local.inputs[WIDTH - 2].clone().into()
                        - AB::Expr::from_u64(NF_PREIMAGE as u64))
                + anchor_start.clone()
                    * (p2_local.inputs[WIDTH - 2].clone().into()
                        - AB::Expr::from_u64(ANCHOR_PREIMAGE as u64)),
        );

        // 7. (production 22) Domain tag in lane 15.
        builder.assert_zero(
            note_start.clone()
                * (p2_local.inputs[WIDTH - 1].clone().into()
                    - AB::Expr::from_u32(Domain::Note as u32))
                + null_start.clone()
                    * (p2_local.inputs[WIDTH - 1].clone().into()
                        - AB::Expr::from_u32(Domain::Nullifier as u32))
                + anchor_start.clone()
                    * (p2_local.inputs[WIDTH - 1].clone().into()
                        - AB::Expr::from_u32(Domain::SpendAnchor as u32)),
        );

        // 8. (production 23) A start row's rate is its first chunk: the public asset
        //     for note sponges, the nullifier-key bus for nullifier and anchor.
        for i in 0..N {
            builder.assert_zero(
                note_start.clone() * (p2_local.inputs[i].clone().into() - pv[PV_ASSET + i].clone())
                    + (null_start.clone() + anchor_start.clone())
                        * (p2_local.inputs[i].clone().into() - local[NK + i].clone().into()),
            );
        }

        // 9. (production 24) Capacity carries through on continuing rows.
        {
            let cont_next: AB::Expr = (0..SPONGE_ROWS)
                .filter(|j| !STARTS.contains(j))
                .map(|j| sp(&next, j))
                .fold(AB::Expr::ZERO, |a, b| a + b);
            let mut when = builder.when_transition();
            for (i, out) in perm_out.iter().enumerate().take(WIDTH).skip(N) {
                when.assert_zero(
                    cont_next.clone() * (p2_next.inputs[i].clone().into() - out.clone().into()),
                );
            }
        }

        // 10. (production 25) Rate carry + absorb injection, tie table identical to
        //     production — including the load-bearing zero ties on each note
        //     sponge's final chunk.
        {
            let zero = AB::Expr::ZERO;
            // The note preimage is `asset ‖ amount(4) ‖ anchor(8) ‖ rnd(8)` = 28,
            // absorbed rate-8 over four rows: [asset] [amount, anchor0..4]
            // [anchor4..8, rnd0..4] [rnd4..8, pad]. The input note's anchor is
            // tied to the `T` bus (the same T the anchor sponge pins `H(nk)` to,
            // which is the authorization binding); its randomness is free. Output
            // notes tie only their amount — anchor and randomness are the payer's
            // free choice, pinned only through the public output commitment.
            let tie = |j: usize, i: usize, next: &[AB::Var]| -> Option<AB::Expr> {
                match j {
                    // C_in (rows 0–3): amount, anchor→T, rnd free.
                    1 if i < 4 => Some(next[AMT_IN + i].clone().into()),
                    1 => Some(next[T + (i - 4)].clone().into()),
                    2 if i < 4 => Some(next[T + 4 + i].clone().into()),
                    2 => None,
                    3 if i < 4 => None,
                    3 => Some(zero.clone()),
                    // Nullifier (rows 4–5): row 5 absorbs the input commitment.
                    5 => Some(pv[PV_INPUT_COMMITMENT + i].clone()),
                    // C_out0 (rows 6–9): amount tied, anchor+rnd free.
                    7 if i < 4 => Some(next[AMT_O0 + i].clone().into()),
                    7 => None,
                    8 => None,
                    9 if i < 4 => None,
                    9 => Some(zero.clone()),
                    // C_out1 (rows 10–13): amount tied, anchor+rnd free.
                    11 if i < 4 => Some(next[AMT_O1 + i].clone().into()),
                    11 => None,
                    12 => None,
                    13 if i < 4 => None,
                    13 => Some(zero.clone()),
                    _ => unreachable!("start rows are not continuing rows"),
                }
            };
            let mut when = builder.when_transition();
            for (i, out) in perm_out.iter().enumerate().take(N) {
                let mut sum = AB::Expr::ZERO;
                for j in (0..SPONGE_ROWS).filter(|j| !STARTS.contains(j)) {
                    if let Some(absorbed) = tie(j, i, &next) {
                        sum += sp(&next, j)
                            * (p2_next.inputs[i].clone().into() - out.clone().into() - absorbed);
                    }
                }
                when.assert_zero(sum);
            }
        }

        // 11. (production 26) Each sponge's final output is the public digest it
        //      claims.
        for (i, out) in perm_out.iter().enumerate().take(N) {
            let mut sum = AB::Expr::ZERO;
            for &(j, slot) in PINS.iter() {
                sum += sp(&local, j) * (out.clone().into() - pv[slot + i].clone());
            }
            builder.assert_zero(sum);
        }

        // 12. (production 32) **The authorization constraint.** The anchor row hashes
        //      the nullifier key and must land on the T bus — the same T the
        //      input commitment absorbed. The spender is forced to know a
        //      preimage of the committed anchor, and the whole statement is
        //      Fiat–Shamir-bound to PV_MSG. In this circuit that is not
        //      belt-and-braces beside a signature; it is the signature.
        for (i, out) in perm_out.iter().enumerate().take(N) {
            builder.assert_zero(
                sp(&local, ANCHOR_ROW) * (out.clone().into() - local[T + i].clone().into()),
            );
        }

        // 13. (production 27) Bus constancy across the section.
        {
            let not_last_sponge: AB::Expr = (0..SPONGE_ROWS - 1)
                .map(|j| sp(&local, j))
                .fold(AB::Expr::ZERO, |a, b| a + b);
            let mut when = builder.when_transition();
            for col in (NK..NK + 2 * N).chain(AMT_IN..AMT_IN + 3 * AMOUNT_LIMBS) {
                when.assert_zero(
                    not_last_sponge.clone()
                        * (next[col].clone().into() - local[col].clone().into()),
                );
            }
        }

        // 14. (production 28) Conservation, exact over u64.
        {
            let g = sp(&local, 0);
            let two16 = AB::Expr::from_u64(1 << 16);
            let limb = |base: usize, k: usize| -> AB::Expr { local[base + k].clone().into() };
            let carry = |k: usize| -> AB::Expr { local[CARRY + k].clone().into() };
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 0) + limb(AMT_O1, 0)
                        - limb(AMT_IN, 0)
                        - two16.clone() * carry(0)),
            );
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 1) + limb(AMT_O1, 1) + carry(0)
                        - limb(AMT_IN, 1)
                        - two16.clone() * carry(1)),
            );
            builder.assert_zero(
                g.clone()
                    * (limb(AMT_O0, 2) + limb(AMT_O1, 2) + carry(1)
                        - limb(AMT_IN, 2)
                        - two16.clone() * carry(2)),
            );
            builder
                .assert_zero(g * (limb(AMT_O0, 3) + limb(AMT_O1, 3) + carry(2) - limb(AMT_IN, 3)));
        }

        // 15. (production 29, 30) Carries and range bits are boolean.
        for k in 0..3 {
            let c: AB::Expr = local[CARRY + k].clone().into();
            builder.assert_zero(c.clone() * (c - AB::Expr::ONE));
        }
        for k in 0..16 {
            let b: AB::Expr = local[RBITS + k].clone().into();
            builder.assert_zero(b.clone() * (b - AB::Expr::ONE));
        }

        // 16. (production 31) Limb range routing.
        {
            let bits_sum: AB::Expr = (0..16)
                .map(|k| local[RBITS + k].clone().into() * AB::Expr::from_u64(1 << k))
                .fold(AB::Expr::ZERO, |a, b: AB::Expr| a + b);
            let mut sum = AB::Expr::ZERO;
            for m in 0..3 * AMOUNT_LIMBS {
                let limb: AB::Expr = local[AMT_IN + m].clone().into();
                sum += sp(&local, m) * (bits_sum.clone() - limb);
            }
            builder.assert_zero(sum);
        }
    }
}

/// Build the transfer trace: 15 sponge rows, padded to [`HEIGHT`].
pub fn generate(w: &TransferWitness) -> RowMajorMatrix<BabyBear> {
    use p3_field::PrimeField32;

    let (mut states, _) = crate::transfer_trace::sponge_states(w);
    while states.len() < HEIGHT {
        states.push([BabyBear::ZERO; WIDTH]);
    }
    let p2 = crate::transfer_trace::p2_columns(states);

    let mut carries = [0u32; 3];
    {
        let l = |a: &[BabyBear; AMOUNT_LIMBS], k: usize| a[k].as_canonical_u32();
        let (i, o0, o1) = (
            &w.input.amount_limbs,
            &w.outputs[0].amount_limbs,
            &w.outputs[1].amount_limbs,
        );
        let mut carry = 0u32;
        for (k, slot) in carries.iter_mut().enumerate() {
            let sum = l(o0, k) + l(o1, k) + carry;
            carry = (sum.wrapping_sub(l(i, k))) >> 16;
            *slot = carry;
        }
    }

    let mut values = vec![BabyBear::ZERO; HEIGHT * NUM_COLS];
    for row in 0..HEIGHT {
        let dst = &mut values[row * NUM_COLS..(row + 1) * NUM_COLS];
        dst[..P2_COLS].copy_from_slice(&p2.values[row * P2_COLS..(row + 1) * P2_COLS]);
        if row >= SPONGE_ROWS {
            continue;
        }
        dst[SP + row] = BabyBear::ONE;
        dst[NK..NK + N].copy_from_slice(&w.input.nullifier_key);
        dst[T..T + N].copy_from_slice(&w.input.anchor);
        dst[AMT_IN..AMT_IN + AMOUNT_LIMBS].copy_from_slice(&w.input.amount_limbs);
        dst[AMT_O0..AMT_O0 + AMOUNT_LIMBS].copy_from_slice(&w.outputs[0].amount_limbs);
        dst[AMT_O1..AMT_O1 + AMOUNT_LIMBS].copy_from_slice(&w.outputs[1].amount_limbs);
        if row == 0 {
            for (k, c) in carries.iter().enumerate() {
                dst[CARRY + k] = BabyBear::from_u32(*c);
            }
        }
        if row < 3 * AMOUNT_LIMBS {
            let limb = match row / AMOUNT_LIMBS {
                0 => w.input.amount_limbs[row % AMOUNT_LIMBS],
                1 => w.outputs[0].amount_limbs[row % AMOUNT_LIMBS],
                _ => w.outputs[1].amount_limbs[row % AMOUNT_LIMBS],
            }
            .as_canonical_u32();
            for k in 0..16 {
                dst[RBITS + k] = BabyBear::from_bool((limb >> k) & 1 == 1);
            }
        }
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_consistent() {
        assert_eq!(HEIGHT, 16, "15 sponge rows pad to 16 — the whole point");
        // The public-value layout: input commitment, nullifier, two outputs,
        // prev history, asset, and the bundle hash. No tips (no signature) and
        // no owner_pk (dropped from the note).
        assert_eq!(NUM_PUBLIC_VALUES, 56);
    }
}

#[cfg(test)]
mod proving_tests {
    use super::*;
    use crate::prove::{
        config, hiding_config, prove_authproto, prove_authproto_hiding, verify_authproto,
        verify_authproto_hiding, TransferPublics,
    };
    use crate::sponge;
    use crate::transfer_trace::NoteOpening;
    use crate::wots;

    fn limbs(v: u64) -> [BabyBear; 4] {
        core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
    }

    fn open(tag: u32, amount_limbs: [BabyBear; 4]) -> NoteOpening {
        let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
        NoteOpening {
            amount_limbs,
            anchor: sponge::hash(Domain::SpendAnchor, &nk),
            nullifier_key: nk,
            randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
        }
    }

    fn commitment(asset: &wots::Digest, o: &NoteOpening) -> wots::Digest {
        let mut p = Vec::new();
        p.extend_from_slice(asset);
        p.extend_from_slice(&o.amount_limbs);
        p.extend_from_slice(&o.anchor);
        p.extend_from_slice(&o.randomness);
        sponge::hash(Domain::Note, &p)
    }

    fn consistent() -> (TransferWitness, TransferPublics) {
        let asset = [BabyBear::from_u32(0xA5); 8];
        let input = open(41, limbs(1000));
        let outs = [open(42, limbs(700)), open(43, limbs(300))];
        let input_commitment = commitment(&asset, &input);
        let mut nf_pre = Vec::new();
        nf_pre.extend_from_slice(&input.nullifier_key);
        nf_pre.extend_from_slice(&input_commitment);
        let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
        let msg = [BabyBear::from_u32(0x1157); 8];
        let publics = TransferPublics::new(
            input_commitment,
            nullifier,
            commitment(&asset, &outs[0]),
            commitment(&asset, &outs[1]),
            [BabyBear::ZERO; 8],
            asset,
        );
        (
            TransferWitness {
                asset,
                input,
                outputs: outs,
                msg,
            },
            publics,
        )
    }

    #[test]
    fn a_consistent_witness_proves_and_verifies() {
        let (w, publics) = consistent();
        let cfg = config();
        let proof = prove_authproto(&cfg, &w, &publics);
        verify_authproto(&cfg, &proof, &publics).expect("an honest hop must verify");

        let hcfg = hiding_config();
        let hproof = prove_authproto_hiding(&hcfg, &w, &publics);
        verify_authproto_hiding(&hcfg, &hproof, &publics).expect("and in the hiding configuration");
    }

    /// **The signature-of-knowledge binding.** The proof must be a statement
    /// about *this* transfer: verifying it against a statement differing in
    /// one field must fail. `TransferPublics::new` derives the bundle hash
    /// from its parts, so tampering `prev_history` changes both that field
    /// and the bundle hash — the two Fiat–Shamir-only publics — and the
    /// refusal below is the transcript binding doing the work. Without this
    /// property a proof could be replayed against a different payment, which
    /// is theft, not a detail.
    #[test]
    fn a_tampered_statement_is_refused() {
        let (w, publics) = consistent();
        let cfg = config();
        let proof = prove_authproto(&cfg, &w, &publics);

        // Rebuilt from the same fixture ingredients with one field changed —
        // `TransferPublics` exposes no getters on purpose (its fields are the
        // statement, and a statement is constructed, not edited).
        let asset = w.asset;
        let input_commitment = commitment(&asset, &w.input);
        let mut nf_pre = Vec::new();
        nf_pre.extend_from_slice(&w.input.nullifier_key);
        nf_pre.extend_from_slice(&input_commitment);
        let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
        let tampered = TransferPublics::new(
            input_commitment,
            nullifier,
            commitment(&asset, &w.outputs[0]),
            commitment(&asset, &w.outputs[1]),
            [BabyBear::from_u32(0xBAD); 8], // a different prev_history
            asset,
        );
        assert!(
            verify_authproto(&cfg, &proof, &tampered).is_err(),
            "a proof must not transplant onto a different statement"
        );
    }

    /// **The authorization control.** A prover who does not know the preimage
    /// of the committed anchor — i.e. is not the payee — must fail. The trace
    /// is built with a foreign nullifier key while the note's commitment holds
    /// the real anchor; constraint 12 (production 32) is the only thing standing between that
    /// prover and someone else's money, exactly as constraint 32 is in
    /// production.
    #[test]
    fn a_spender_without_the_anchor_preimage_is_refused() {
        let (mut w, _) = consistent();
        // The attacker's key. The anchor inside the commitment stays the real
        // one (the attacker cannot change it — it is committed), so the anchor
        // row hashes the wrong key and must miss the T bus.
        w.input.nullifier_key = [BabyBear::from_u32(0xE711); 8];

        // The attacker derives the nullifier their key would produce and
        // claims it publicly — this is precisely the "spend someone else's
        // note under your own nullifier" forgery.
        let asset = w.asset;
        let input_commitment = commitment(&asset, &w.input);
        let mut nf_pre = Vec::new();
        nf_pre.extend_from_slice(&w.input.nullifier_key);
        nf_pre.extend_from_slice(&input_commitment);
        let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
        let publics = TransferPublics::new(
            input_commitment,
            nullifier,
            commitment(&asset, &w.outputs[0]),
            commitment(&asset, &w.outputs[1]),
            [BabyBear::ZERO; 8],
            asset,
        );

        let cfg = config();
        // Debug builds panic in check_constraints; release builds emit a proof
        // that must fail verification. Either way the forgery dies.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let proof = prove_authproto(&cfg, &w, &publics);
            verify_authproto(&cfg, &proof, &publics)
        }));
        match outcome {
            Err(_) => {}     // refused at proving time
            Ok(Err(_)) => {} // refused at verification time
            Ok(Ok(())) => panic!("a spender without the anchor preimage was accepted"),
        }
    }
}
