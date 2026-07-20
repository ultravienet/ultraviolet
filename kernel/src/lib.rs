//! # ultraviolet-kernel
//!
//! Consensus-critical types for the Ultraviolet protocol — a post-quantum,
//! client-side-validated asset protocol on Bitcoin (see spec/ at the
//! repository root).
//!
//! Scope of this crate (v0.1, fungible-first):
//! - [`note`]: notes and their hash commitments — the unit of state
//! - [`nullifier`]: deterministic nullifiers and the 64-byte on-chain record
//! - [`address`]: PQ-signed address records distributed over Nostr
//! - [`receipt`]: relay finality receipts and equivocation fraud proofs
//! - [`hash`]: the boundary-hash abstraction (SHA-256 always at protocol
//!   boundaries; the `perf-hash` feature selects arithmetization-friendly
//!   hashing inside recursion)
//! - [`sig`]: the signature abstraction (SLH-DSA behind the `slh` feature)
//!
//! Deliberately absent, arriving next: the SP1 guest program that proves
//! state transitions (raw STARK output only — no SNARK wrapper, which would
//! reintroduce pairings and a trusted setup), value-conservation circuits,
//! and ML-KEM note encryption. This crate is MIT/Apache-2.0 so it stays
//! embeddable anywhere; the Blacklight client (AGPL, fork of White Noise)
//! depends on it, never the reverse.

pub mod address;
pub mod channel;
pub mod hash;
pub mod hashlock;
pub mod history;
pub mod note;
pub mod nullifier;
pub mod receipt;
pub mod sig;
pub mod transfer;

pub use hash::Hash256;
pub use note::{Note, NoteCommitment};
pub use nullifier::{Nullifier, Record};
pub use receipt::{FraudProof, Receipt};
pub use transfer::{validate_transition, SpendInput, Transfer, TransitionResult};
