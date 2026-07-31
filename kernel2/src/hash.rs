//! The money path's one hash — re-exported from `uv-air`.
//!
//! The sponge lives in [`uv_air::sponge`] because the transfer circuit's
//! witness generation must be the *same computation* as the host hash, not a
//! second implementation agreeing by luck. Everything documented there — the
//! construction, the capacity slots, the domain tags — is consensus for this
//! crate too. This module exists so kernel2 callers keep one import path.

pub use uv_air::sponge::{absorb_states, hash, Domain};
