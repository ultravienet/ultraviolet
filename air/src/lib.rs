//! Ultraviolet's sovereign STARK.
//!
//! One hand-written AIR proves one money-path hop: 16 rows, 361 columns, 16
//! constraints, ~0.01-0.02 s and 117 KB hiding (`SPEC.md` §8). Every hash in it
//! is Poseidon2 and there is no signature; authorization is the spender proving
//! it knows the preimage of the note's spend anchor.
//!
//! Because the circuit is ours, its soundness is ours: a column nobody
//! constrains is a free variable, and a free variable in the wrong place mints
//! money. Two artifacts carry that argument and both must stay at their
//! headline — the mutation sweep (16 of 16 constraints load-bearing) and
//! `tests/every_column_is_constrained.rs` (361 of 361 columns). `air/COVERAGE.md`
//! states what they do *not* cover.
//!
//! - [`sponge`]: the one domain-separated hash, shared by host and circuit.
//! - [`poseidon2_eval`]: the in-circuit permutation, differentially tested
//!   against the host so the two can never drift.
pub mod authproto_air;
pub mod poseidon2;
pub mod poseidon2_eval;
pub mod prove;
pub mod sponge;
pub mod transfer_trace;
