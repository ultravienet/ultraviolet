//! Witness generation for [`crate::wots_air`].
//!
//! One row per chain step. For chain `i` with digit `d_i`, verification walks the
//! revealed signature value `W-1-d_i` times, so the first `W-1-d_i` rows are
//! active (`sel = 1`) and the rest are padding that permutes and discards.
//!
//! Poseidon2 columns come from upstream's public `generate_trace_rows`, so the
//! witness is produced by the same code path upstream's own AIR is tested
//! against — one less place for host and circuit to drift. (The per-row helper
//! `generate_trace_rows_for_perm` writes into `MaybeUninit`, which would mean
//! unsafe transmutation inside consensus-critical code; the batch form is safe
//! and costs one allocation.)

use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;

use p3_field::Field;

use crate::wots::{self, Digest};
use crate::wots::{CHAINS, LOG_W, N, WIDTH};
use crate::wots_air::{
    ACC, BITS, CHAIN_IN, CHAIN_OUT, CHAIN_ROWS, DIGIT, HALF_FULL_ROUNDS, IS_LAST, NUM_COLS, OH,
    P2_COLS, PARTIAL_ROUNDS, PINV, POS, ROWS_PER_CHAIN, SBOX_DEGREE, SBOX_REGISTERS, SEL,
};

/// The chain section's raw rows: permutation states, chain values, and flags.
///
/// Shared by the standalone WOTS+ trace and the transfer trace so the chain
/// walk — consensus-critical — exists once.
pub(crate) struct ChainRows {
    pub states: Vec<[BabyBear; WIDTH]>,
    pub chain_in: Vec<Digest>,
    pub chain_out: Vec<Digest>,
    /// (sel, is_last, digit, running active-step count)
    pub flags: Vec<(bool, bool, u8, u32)>,
}

/// Walk every chain on the host, recording each step. This is the same walk
/// `wots::verify` performs, which is the point — the circuit constrains that
/// computation. Returns exactly `CHAIN_ROWS` rows, no padding.
pub(crate) fn chain_rows(msg: &Digest, sig: &wots::Signature) -> ChainRows {
    let perm = wots::permutation();
    let digits = wots::digits(msg);

    let mut states: Vec<[BabyBear; WIDTH]> = Vec::with_capacity(CHAIN_ROWS);
    let mut chain_in: Vec<Digest> = Vec::with_capacity(CHAIN_ROWS);
    let mut chain_out: Vec<Digest> = Vec::with_capacity(CHAIN_ROWS);
    let mut flags: Vec<(bool, bool, u8, u32)> = Vec::with_capacity(CHAIN_ROWS);

    for (c, &digit) in digits.iter().enumerate() {
        // Verification walks the revealed value the *remaining* steps.
        let active = wots::W - 1 - digit as usize;
        let mut value = sig.0[c];
        let mut acc = 0u32;
        for s in 0..ROWS_PER_CHAIN {
            let sel = s < active;
            acc += u32::from(sel);
            let mut state = [BabyBear::ZERO; WIDTH];
            state[..N].copy_from_slice(&value);
            states.push(state);
            chain_in.push(value);
            let out = if sel {
                wots::step(&perm, &value)
            } else {
                value
            };
            chain_out.push(out);
            flags.push((sel, s + 1 == ROWS_PER_CHAIN, digit, acc));
            value = out;
        }
        debug_assert_eq!(
            acc as usize + digit as usize,
            wots::W - 1,
            "walk length must satisfy the circuit's acc + digit == W-1"
        );
    }

    ChainRows {
        states,
        chain_in,
        chain_out,
        flags,
    }
}

/// The inert bookkeeping a non-chain row carries: `sel = 0`, `is_last` exactly
/// where the position cycle hits a boundary, digit `W-1` (so `acc + digit ==
/// W-1` holds with `acc = 0`), zero chain values.
pub(crate) fn inert_flags(row: usize) -> (bool, bool, u8, u32) {
    let pos = row % ROWS_PER_CHAIN;
    (false, pos == ROWS_PER_CHAIN - 1, (wots::W - 1) as u8, 0)
}

/// Build the verification trace for `sig` against `msg`.
///
/// Height is `CHAINS * ROWS_PER_CHAIN` rounded up to a power of two, which the
/// prover requires. Padding rows are inert per [`inert_flags`]: rows
/// 1005..1019 form one complete pseudo-chain (`is_last` only at its boundary —
/// constraint 14 pins that equivalence, so padding may no longer mark every
/// row last), the rest a truncated cycle whose final-row checks never fire.
pub fn generate(msg: &Digest, sig: &wots::Signature) -> RowMajorMatrix<BabyBear> {
    let height = (CHAINS * ROWS_PER_CHAIN).next_power_of_two();
    let ChainRows {
        mut states,
        mut chain_in,
        mut chain_out,
        mut flags,
    } = chain_rows(msg, sig);

    while states.len() < height {
        flags.push(inert_flags(states.len()));
        states.push([BabyBear::ZERO; WIDTH]);
        chain_in.push([BabyBear::ZERO; N]);
        chain_out.push([BabyBear::ZERO; N]);
    }

    // Pass 2: upstream fills the Poseidon2 columns for all rows at once.
    let p2 = p2_columns(states);

    // Pass 3: widen each row with the chain columns.
    let mut values = vec![BabyBear::ZERO; height * NUM_COLS];
    for row in 0..height {
        fill_shared_row(
            &mut values[row * NUM_COLS..(row + 1) * NUM_COLS],
            row,
            &p2.values[row * P2_COLS..(row + 1) * P2_COLS],
            &chain_in[row],
            &chain_out[row],
            flags[row],
        );
    }

    RowMajorMatrix::new(values, NUM_COLS)
}

/// Fill one row's shared columns — the Poseidon2 block, chain values, flags,
/// and the closed-form binding columns (OH/POS/PINV). `row_values` may be
/// wider than [`NUM_COLS`]: the transfer trace calls this for its first
/// [`NUM_COLS`] columns and fills its own registers after.
///
/// The binding columns are closed-form in the row index; the AIR's constraints
/// force exactly these values, so any deviation here would show up as an
/// unprovable honest witness, not a soundness change.
pub(crate) fn fill_shared_row(
    row_values: &mut [BabyBear],
    row: usize,
    p2_row: &[BabyBear],
    chain_in: &Digest,
    chain_out: &Digest,
    flags: (bool, bool, u8, u32),
) {
    row_values[..P2_COLS].copy_from_slice(p2_row);
    row_values[CHAIN_IN..CHAIN_IN + N].copy_from_slice(chain_in);
    row_values[CHAIN_OUT..CHAIN_OUT + N].copy_from_slice(chain_out);
    let (sel, is_last, digit, acc) = flags;
    row_values[SEL] = BabyBear::from_bool(sel);
    row_values[IS_LAST] = BabyBear::from_bool(is_last);
    row_values[DIGIT] = BabyBear::from_u32(u32::from(digit));
    for k in 0..LOG_W {
        row_values[BITS + k] = BabyBear::from_bool((digit >> k) & 1 == 1);
    }
    row_values[ACC] = BabyBear::from_u32(acc);

    if row < CHAIN_ROWS {
        row_values[OH + row / ROWS_PER_CHAIN] = BabyBear::ONE;
    }
    let pos = row % ROWS_PER_CHAIN;
    row_values[POS] = BabyBear::from_u32(pos as u32);
    row_values[PINV] = if pos == ROWS_PER_CHAIN - 1 {
        // On boundary rows the constraint `(pos-14)*pinv = 1-is_last` reads
        // 0 = 0; the cell is free and zero is the tidy choice.
        BabyBear::ZERO
    } else {
        (BabyBear::from_u32(pos as u32) - BabyBear::from_u32((ROWS_PER_CHAIN - 1) as u32)).inverse()
    };
}

/// Upstream's Poseidon2 trace filler over a full state list — shared with the
/// transfer trace so both circuits' permutation columns come from the same
/// code path.
pub(crate) fn p2_columns(states: Vec<[BabyBear; WIDTH]>) -> RowMajorMatrix<BabyBear> {
    let p2 = generate_trace_rows::<
        BabyBear,
        GenericPoseidon2LinearLayersBabyBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(states, &upstream_constants(), 0);
    debug_assert_eq!(p2.width, P2_COLS, "vendored layout must match upstream");
    p2
}

/// The tips each chain ends on — what the public key is compressed from.
///
/// Read out of the finished trace rather than recomputed, so a bug in trace
/// generation shows up as a public-key mismatch instead of hiding.
pub fn tips_from_trace(trace: &RowMajorMatrix<BabyBear>) -> [Digest; CHAINS] {
    // Index by the trace's own width: the transfer trace is wider than the
    // standalone one, and the chain columns sit at the same offsets in both.
    let width = trace.width;
    let mut tips = [[BabyBear::ZERO; N]; CHAINS];
    for (c, tip) in tips.iter_mut().enumerate() {
        let row = c * ROWS_PER_CHAIN + (ROWS_PER_CHAIN - 1);
        let base = row * width;
        for (i, slot) in tip.iter_mut().enumerate() {
            *slot = trace.values[base + CHAIN_OUT + i];
        }
    }
    tips
}

/// Upstream's `RoundConstants`, built from the published BabyBear tables.
///
/// `RoundConstants::new` is public even though its fields are not, so the
/// witness generator can use upstream's type while the *constraints* use our
/// own [`crate::poseidon2_eval::Constants`]. Both are built from the same three
/// `p3_baby_bear` tables, by symbol rather than by copied literals, so host and
/// circuit read the same arrays. `wots_air::tests::constants_match_the_host_permutation`
/// pins all three, and `air/tests/poseidon2_differential.rs` checks the two
/// permutations agree over the full state on random inputs.
fn upstream_constants(
) -> p3_poseidon2_air::RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    use p3_baby_bear::{
        BABYBEAR_RC16_EXTERNAL_FINAL, BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
    };
    p3_poseidon2_air::RoundConstants::new(
        BABYBEAR_RC16_EXTERNAL_INITIAL,
        BABYBEAR_RC16_INTERNAL,
        BABYBEAR_RC16_EXTERNAL_FINAL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;

    fn msg_of(tag: u32) -> Digest {
        let perm = wots::permutation();
        let mut s = [BabyBear::ZERO; WIDTH];
        s[0] = BabyBear::from_u32(tag);
        use p3_symmetric::Permutation;
        perm.permute_mut(&mut s);
        let mut d = [BabyBear::ZERO; N];
        d.copy_from_slice(&s[..N]);
        d
    }

    /// The trace must reach exactly the tips the host reaches — otherwise the
    /// circuit is verifying a different computation than `wots::verify`.
    #[test]
    fn trace_tips_match_the_host_verification() {
        let perm = wots::permutation();
        let seed = [21u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(5);
        let sig = wots::sign(&perm, &seed, &msg);
        assert!(
            wots::verify(&perm, &pk, &msg, &sig),
            "host must accept first"
        );

        let trace = generate(&msg, &sig);
        let tips = tips_from_trace(&trace);
        assert_eq!(
            wots::compress(&perm, &tips),
            pk,
            "trace tips must compress to the public key"
        );
    }

    /// A signature the host rejects must not produce the right tips either.
    #[test]
    fn a_forged_signature_does_not_reach_the_public_key() {
        let perm = wots::permutation();
        let seed = [22u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(6);
        let mut sig = wots::sign(&perm, &seed, &msg);
        sig.0[9][0] += BabyBear::ONE;
        assert!(!wots::verify(&perm, &pk, &msg, &sig));

        let trace = generate(&msg, &sig);
        let tips = tips_from_trace(&trace);
        assert_ne!(wots::compress(&perm, &tips), pk);
    }

    #[test]
    fn trace_shape_is_right_and_padding_is_inert() {
        let perm = wots::permutation();
        let seed = [23u8; 32];
        let msg = msg_of(7);
        let sig = wots::sign(&perm, &seed, &msg);
        let trace = generate(&msg, &sig);

        assert_eq!(trace.width(), NUM_COLS);
        assert_eq!(
            trace.height(),
            (CHAINS * ROWS_PER_CHAIN).next_power_of_two()
        );
        assert!(trace.height().is_power_of_two());

        // Padding rows must not advance anything, must keep the position cycle
        // running (is_last exactly where pos hits the boundary), and must carry
        // an all-zero one-hot register — that is what marks them as padding.
        for row in (CHAINS * ROWS_PER_CHAIN)..trace.height() {
            let base = row * NUM_COLS;
            let pos = row % ROWS_PER_CHAIN;
            assert_eq!(trace.values[base + SEL], BabyBear::ZERO);
            assert_eq!(
                trace.values[base + IS_LAST],
                BabyBear::from_bool(pos == ROWS_PER_CHAIN - 1)
            );
            for j in 0..CHAINS {
                assert_eq!(trace.values[base + OH + j], BabyBear::ZERO);
            }
        }
    }

    /// The binding columns are closed-form in the row index; pin the closed form.
    #[test]
    fn binding_columns_match_their_closed_form() {
        let perm = wots::permutation();
        let seed = [25u8; 32];
        let msg = msg_of(9);
        let sig = wots::sign(&perm, &seed, &msg);
        let trace = generate(&msg, &sig);

        for row in 0..trace.height() {
            let base = row * NUM_COLS;
            let pos = row % ROWS_PER_CHAIN;
            assert_eq!(trace.values[base + POS], BabyBear::from_u32(pos as u32));
            if pos == ROWS_PER_CHAIN - 1 {
                assert_eq!(trace.values[base + PINV], BabyBear::ZERO);
            } else {
                // (pos - 14) * pinv must be 1 — the inverse really is one.
                let diff = BabyBear::from_u32(pos as u32)
                    - BabyBear::from_u32((ROWS_PER_CHAIN - 1) as u32);
                assert_eq!(diff * trace.values[base + PINV], BabyBear::ONE);
            }
            for j in 0..CHAINS {
                let expect = row < CHAIN_ROWS && j == row / ROWS_PER_CHAIN;
                assert_eq!(
                    trace.values[base + OH + j],
                    BabyBear::from_bool(expect),
                    "one-hot register wrong at row {row} col {j}"
                );
            }
        }
    }

    /// Active-row counts must equal `W-1-d_i`. If this drifts, the circuit walks
    /// chains the wrong number of times and the tips silently diverge.
    #[test]
    fn selector_pattern_encodes_the_digits() {
        let perm = wots::permutation();
        let seed = [24u8; 32];
        let msg = msg_of(8);
        let sig = wots::sign(&perm, &seed, &msg);
        let digits = wots::digits(&msg);
        let trace = generate(&msg, &sig);

        for (c, &digit) in digits.iter().enumerate() {
            let active: usize = (0..ROWS_PER_CHAIN)
                .filter(|s| {
                    trace.values[(c * ROWS_PER_CHAIN + s) * NUM_COLS + SEL] == BabyBear::ONE
                })
                .count();
            assert_eq!(
                active,
                wots::W - 1 - digit as usize,
                "chain {c} walked the wrong number of steps"
            );
        }
    }
}
