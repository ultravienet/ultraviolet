//! Witness generation for [`crate::transfer_air`].
//!
//! The chain section reuses [`crate::trace`]'s pass wholesale (one consensus
//! walk, two circuits); the sponge section's states come from
//! [`crate::sponge::absorb_states`] — the same function the host hash is
//! defined on — so witness and hash cannot drift.
//!
//! This crate deliberately knows nothing about kernel2's `Note` type: the
//! witness arrives as raw field values, and `uv-kernel2`'s wrapper is what
//! maps notes into it (and is the consensus verify entry point).

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::sponge::{absorb_states, Domain};
use crate::trace::{chain_rows, fill_shared_row, inert_flags, p2_columns, ChainRows};
use crate::transfer_air::{
    AMOUNT_LIMBS, AMT_IN, AMT_O0, AMT_O1, CARRY, NF_PREIMAGE, NK, NOTE_PREIMAGE, NUM_COLS, RBITS,
    SP, SPONGE_ROWS, T,
};
use crate::wots::{self, Digest, N, WIDTH};
use crate::wots_air::{CHAIN_ROWS, P2_COLS};

/// One note's opening — everything its commitment binds.
#[derive(Clone)]
pub struct NoteOpening {
    pub amount_limbs: [BabyBear; AMOUNT_LIMBS],
    pub owner_pk: Digest,
    /// The **secret** nullifier key. Only the input note's opening needs a
    /// real one; outputs are built by a payer who does not have theirs, so
    /// output openings carry the anchor alone and leave this unused.
    pub nullifier_key: Digest,
    /// The committed spend anchor `t = H(nullifier_key)`.
    pub anchor: Digest,
    pub randomness: Digest,
}

impl NoteOpening {
    /// The commitment preimage, in the exact order `kernel2::note` hashes it.
    fn preimage(&self, asset: &Digest) -> Vec<BabyBear> {
        let mut p = Vec::with_capacity(NOTE_PREIMAGE);
        p.extend_from_slice(asset);
        p.extend_from_slice(&self.amount_limbs);
        p.extend_from_slice(&self.owner_pk);
        p.extend_from_slice(&self.anchor);
        p.extend_from_slice(&self.randomness);
        debug_assert_eq!(p.len(), NOTE_PREIMAGE);
        p
    }
}

/// The full private witness of one hop.
pub struct TransferWitness {
    pub asset: Digest,
    pub input: NoteOpening,
    pub outputs: [NoteOpening; 2],
    /// The bundle hash — public, but the trace needs it for the WOTS+ walk.
    pub msg: Digest,
    /// Signature over `msg` under `input.owner_pk`.
    pub sig: wots::Signature,
}

/// The sponge section's pre-permutation states, in row order.
fn sponge_states(w: &TransferWitness) -> (Vec<[BabyBear; WIDTH]>, Digest) {
    let c_in_pre = w.input.preimage(&w.asset);
    let mut states = absorb_states(Domain::Note, &c_in_pre);
    let c_in = crate::sponge::hash(Domain::Note, &c_in_pre);

    let mut nf_pre = Vec::with_capacity(NF_PREIMAGE);
    nf_pre.extend_from_slice(&w.input.nullifier_key);
    nf_pre.extend_from_slice(&c_in);
    states.extend(absorb_states(Domain::Nullifier, &nf_pre));

    for out in &w.outputs {
        states.extend(absorb_states(Domain::Note, &out.preimage(&w.asset)));
    }
    // The anchor row, last: t = H(nk). One absorb, and its output is pinned to
    // the T bus that the input commitment absorbed.
    states.extend(absorb_states(Domain::SpendAnchor, &w.input.nullifier_key));
    debug_assert_eq!(states.len(), SPONGE_ROWS);
    (states, c_in)
}

/// Build the transfer trace: chain section, sponge section, padding.
pub fn generate(w: &TransferWitness) -> RowMajorMatrix<BabyBear> {
    let height = (CHAIN_ROWS + SPONGE_ROWS).next_power_of_two();
    let ChainRows {
        mut states,
        chain_in,
        chain_out,
        flags,
    } = chain_rows(&w.msg, &w.sig);

    let (sponge, _) = sponge_states(w);
    states.extend(sponge);
    while states.len() < height {
        states.push([BabyBear::ZERO; WIDTH]);
    }
    let p2 = p2_columns(states);

    // Conservation carries, computed exactly as constraint 28 reads them.
    let mut carries = [0u32; 3];
    {
        let l = |a: &[BabyBear; AMOUNT_LIMBS], k: usize| {
            use p3_field::PrimeField32;
            a[k].as_canonical_u32()
        };
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

    let zero = [BabyBear::ZERO; N];
    let mut values = vec![BabyBear::ZERO; height * NUM_COLS];
    for row in 0..height {
        let dst = &mut values[row * NUM_COLS..(row + 1) * NUM_COLS];
        let (ci, co, fl) = if row < CHAIN_ROWS {
            (&chain_in[row], &chain_out[row], flags[row])
        } else {
            (&zero, &zero, inert_flags(row))
        };
        fill_shared_row(
            &mut dst[..crate::wots_air::NUM_COLS],
            row,
            &p2.values[row * P2_COLS..(row + 1) * P2_COLS],
            ci,
            co,
            fl,
        );

        if !(CHAIN_ROWS..CHAIN_ROWS + SPONGE_ROWS).contains(&row) {
            continue;
        }
        let j = row - CHAIN_ROWS;
        dst[SP + j] = BabyBear::ONE;

        // The buses: constant across the whole section.
        dst[NK..NK + N].copy_from_slice(&w.input.nullifier_key);
        dst[T..T + N].copy_from_slice(&w.input.anchor);
        dst[AMT_IN..AMT_IN + AMOUNT_LIMBS].copy_from_slice(&w.input.amount_limbs);
        dst[AMT_O0..AMT_O0 + AMOUNT_LIMBS].copy_from_slice(&w.outputs[0].amount_limbs);
        dst[AMT_O1..AMT_O1 + AMOUNT_LIMBS].copy_from_slice(&w.outputs[1].amount_limbs);
        // Carries live where constraint 28 reads them (SP[0]); zero elsewhere
        // is boolean, so constraint 29 is satisfied everywhere.
        if j == 0 {
            for (k, c) in carries.iter().enumerate() {
                dst[CARRY + k] = BabyBear::from_u32(*c);
            }
        }
        // Range bits: section row m decomposes the m-th limb (constraint 31).
        if j < 3 * AMOUNT_LIMBS {
            use p3_field::PrimeField32;
            let limb = match j / AMOUNT_LIMBS {
                0 => w.input.amount_limbs[j % AMOUNT_LIMBS],
                1 => w.outputs[0].amount_limbs[j % AMOUNT_LIMBS],
                _ => w.outputs[1].amount_limbs[j % AMOUNT_LIMBS],
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
    use p3_matrix::Matrix;

    fn opening(tag: u32, amount: u64) -> NoteOpening {
        let seed = [tag as u8; 32];
        let perm = wots::permutation();
        let nullifier_key = [BabyBear::from_u32(tag * 7 + 1); N];
        NoteOpening {
            amount_limbs: core::array::from_fn(|i| {
                BabyBear::from_u32(((amount >> (16 * i)) & 0xFFFF) as u32)
            }),
            owner_pk: wots::public_key(&perm, &seed),
            anchor: crate::sponge::hash(Domain::SpendAnchor, &nullifier_key),
            nullifier_key,
            randomness: [BabyBear::from_u32(tag * 11 + 3); N],
        }
    }

    #[test]
    fn the_trace_has_the_right_shape_and_sponge_states() {
        let perm = wots::permutation();
        let asset = [BabyBear::from_u32(5); N];
        let input = opening(1, 100);
        let outputs = [opening(2, 60), opening(3, 40)];
        let msg = [BabyBear::from_u32(9); N];
        let sig = wots::sign(&perm, &[1u8; 32], &msg);
        let w = TransferWitness {
            asset,
            input,
            outputs,
            msg,
            sig,
        };

        let t = generate(&w);
        assert_eq!(t.width(), NUM_COLS);
        assert_eq!(t.height(), 1024);

        // The sponge section's permutation inputs must equal the host's
        // absorb states — the differential tie between circuit and hash.
        // Poseidon2Cols puts an `export` flag at offset 0; inputs start at 1.
        let (states, _) = sponge_states(&w);
        for (j, st) in states.iter().enumerate() {
            let row = CHAIN_ROWS + j;
            let base = row * NUM_COLS;
            for (i, expect) in st.iter().enumerate() {
                assert_eq!(
                    t.values[base + 1 + i],
                    *expect,
                    "sponge state mismatch at row {row} lane {i}"
                );
            }
            assert_eq!(t.values[base + SP + j], BabyBear::ONE);
        }
    }
}
