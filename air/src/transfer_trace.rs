//! The transfer witness, and the sponge-section states the circuit absorbs.
//!
//! `NoteOpening` and `TransferWitness` are the private inputs a hop proves over;
//! `sponge_states` turns them into the pre-permutation states of the sponge
//! section, shared by the transfer circuit (`authproto_air`) so the trace is the
//! production sponge by construction rather than by copy.

use p3_baby_bear::{
    BabyBear, GenericPoseidon2LinearLayersBabyBear, BABYBEAR_RC16_EXTERNAL_FINAL,
    BABYBEAR_RC16_EXTERNAL_INITIAL, BABYBEAR_RC16_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::{generate_trace_rows, RoundConstants};

use crate::poseidon2::{Digest, WIDTH};
use crate::poseidon2_eval::{
    HALF_FULL_ROUNDS, P2_COLS, PARTIAL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
};
use crate::sponge::{absorb_states, Domain, AMOUNT_LIMBS, NF_PREIMAGE, NOTE_PREIMAGE, SPONGE_ROWS};

/// One note's opening — everything its commitment binds.
#[derive(Clone)]
pub struct NoteOpening {
    pub amount_limbs: [BabyBear; AMOUNT_LIMBS],
    /// The **secret** nullifier key. Only the input note's opening needs a
    /// real one; outputs are built by a payer who does not have theirs, so
    /// output openings carry the anchor alone and leave this unused.
    pub nullifier_key: Digest,
    /// The committed spend anchor `t = H(nullifier_key)`.
    pub anchor: Digest,
    pub randomness: Digest,
}

impl NoteOpening {
    /// The commitment preimage, in the exact order `kernel2::note` hashes it —
    /// `asset ‖ amount ‖ anchor ‖ rnd`, no `owner_pk` (spec/99 `[PROOF-AUTH]`).
    fn preimage(&self, asset: &Digest) -> Vec<BabyBear> {
        let mut p = Vec::with_capacity(NOTE_PREIMAGE);
        p.extend_from_slice(asset);
        p.extend_from_slice(&self.amount_limbs);
        p.extend_from_slice(&self.anchor);
        p.extend_from_slice(&self.randomness);
        debug_assert_eq!(p.len(), NOTE_PREIMAGE);
        p
    }
}

/// The full private witness of one hop.
///
/// Authorization is the anchor preimage: the spender supplies
/// `input.nullifier_key` and the circuit checks it hashes to the anchor the note
/// committed to (spec/99 `[PROOF-AUTH]`). `msg` is the bundle hash, public,
/// bound to the proof through Fiat–Shamir over the public values.
pub struct TransferWitness {
    pub asset: Digest,
    pub input: NoteOpening,
    pub outputs: [NoteOpening; 2],
    pub msg: Digest,
}

/// The sponge section's pre-permutation states, in row order — five note/anchor
/// sponges and the nullifier sponge, exactly what the transfer circuit absorbs.
pub(crate) fn sponge_states(w: &TransferWitness) -> (Vec<[BabyBear; WIDTH]>, Digest) {
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

/// Generate the Poseidon2 permutation columns for a sequence of pre-permutation
/// states. The witness generator and the constraints both go through this one
/// code path, so the trace's permutation is exactly the one the AIR checks.
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

/// Upstream's `RoundConstants`, built from the published BabyBear tables — the
/// same three `p3_baby_bear` arrays `poseidon2_eval::constants` uses, so the
/// witness generator's permutation and the constraints' permutation agree.
fn upstream_constants() -> RoundConstants<BabyBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        BABYBEAR_RC16_EXTERNAL_INITIAL,
        BABYBEAR_RC16_INTERNAL,
        BABYBEAR_RC16_EXTERNAL_FINAL,
    )
}
