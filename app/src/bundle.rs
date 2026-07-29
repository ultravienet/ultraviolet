//! The payment bundle: what travels, sealed, from payer to payee.
//!
//! Shared because both callers speak it — the CLI seals one per payment and
//! the phone opens the same bytes. One definition, or the two ends of the wire
//! drift.

use serde::{Deserialize, Serialize};
use uv_wallet2::accept::Lineage;

/// What travels to the payee: which request this pays, and the full lineage.
///
/// The payee reconstructs the note from their own derivation — the sender
/// never sends secrets, only which slot they paid and the history that proves
/// the payment.
#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub index: u64,
    pub amount: u64,
    pub asset_hex: String,
    pub lineage: Lineage,
}
