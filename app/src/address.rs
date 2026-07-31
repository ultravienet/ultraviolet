//! The address: what a payee hands a payer, once, on first contact.
//!
//! Shared because both callers speak the same file — the CLI writes and reads
//! it today, the phone will display and generate the same shape — and the
//! address is the other half of the wire the bundle travels back along.

use serde::{Deserialize, Serialize};

/// One payment slot: everything a payer needs to build a note for this payee,
/// and nothing that lets the payer spend it or watch it.
///
/// Per-slot by decision (spec/99 `[ANCHOR-REUSE]`): each slot's anchor is used
/// once, so no secret of the payee's outlives the spend it authorizes. The
/// alternative — one long-lived anchor anyone could pay — would put that
/// secret in every spend's witness, and is gated on the circuit review.
#[derive(Clone, Serialize, Deserialize)]
pub struct Slot {
    pub index: u64,
    pub nullifier_anchor_hex: String,
    pub randomness_hex: String,
}

/// An address: a batch of unused slots, handed over once on first contact.
///
/// This is Signal's prekey pattern, and it is the honest shape of a
/// "non-interactive" address over hash-based keys. There is no per-payment
/// invoice — a payer takes the next unused slot and pays whenever it likes,
/// with the payee offline. What it does need is that first handover, and
/// replenishment before the batch runs out.
#[derive(Serialize, Deserialize)]
pub struct Address {
    /// Where to seal payments to. Hybrid ML-KEM-768 + X25519 — off the money
    /// path, so a lattice break costs privacy and never a coin.
    pub scan: uv_envelope::ScanPublic,
    pub slots: Vec<Slot>,
}
