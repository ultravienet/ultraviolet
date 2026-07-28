//! Ultraviolet's sovereign STARK.
//!
//! Phase A established (spec/04) that the zkVM, not the cryptography, is the
//! bottleneck: a hand-written Poseidon2 AIR does one WOTS+ verification's hashing
//! in 0.040 s / 137.7 KB / 111 MB against SP1's 124 s / 1,242 KB / 9.67 GB.
//!
//! - [`wots`]: WOTS+ over Poseidon2, the host-side reference implementation. The
//!   AIR is differentially tested against it, which is how the host/circuit
//!   parity that the zkVM gave for free gets preserved.
pub mod poseidon2_eval;
pub mod prove;
pub mod sponge;
pub mod trace;
pub mod transfer_air;
pub mod transfer_trace;
pub mod wots;
pub mod wots_air;
