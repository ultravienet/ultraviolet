//! SP1 guest: prove one Ultraviolet hop of proof-carrying data.
//!
//! Genesis hop: validate the transition, start the history digest.
//! Chained hop: **verify the previous hop's proof in-circuit**, check that
//! this transfer only spends notes the previous hop created, advance the
//! digest. A receiver therefore verifies exactly one proof for any history
//! depth — O(1) receive (spec/04-PROOFS.md).
//!
//! Committed output is the fixed-layout [`HopOutput`] encoding (so the next
//! hop can recompute this hop's public-values digest exactly). The vkey is
//! carried in the output and must be constant along a chain. The proof is
//! the raw SP1 STARK — no SNARK wrapper, ever.

#![no_main]
sp1_zkvm::entrypoint!(main);

use ultraviolet_kernel::history::{
    advance_history, check_linkage, public_values_digest, HopInput, HopOutput, HopPublic,
    GENESIS_DIGEST,
};
use ultraviolet_kernel::transfer::validate_transition;

pub fn main() {
    let input = sp1_zkvm::io::read::<HopInput>();

    let output = match input {
        HopInput::Genesis { transfer, vkey } => {
            let result = validate_transition(&transfer).expect("invalid transition");
            let history_digest = advance_history(&GENESIS_DIGEST, &result);
            HopOutput { vkey, public: HopPublic { result, history_digest } }
        }
        HopInput::Chained { transfer, prev, vkey } => {
            // The chain's vkey must be constant: the previous hop committed
            // to the same guest we are verifying it with.
            assert_eq!(prev.vkey, vkey, "vkey must be constant along a chain");

            // Verify the previous hop's proof inside the zkVM.
            let prev_digest = public_values_digest(&prev);
            sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &prev_digest);

            // This transfer may only spend notes the previous hop created.
            check_linkage(&prev.public.result, &transfer).expect("unknown input note");

            let result = validate_transition(&transfer).expect("invalid transition");
            let history_digest = advance_history(&prev.public.history_digest, &result);
            HopOutput { vkey, public: HopPublic { result, history_digest } }
        }
    };

    sp1_zkvm::io::commit_slice(&output.encode());
}
