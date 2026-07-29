//! The parts of `uv` that more than one binary needs.
//!
//! `uv` itself is a binary, and so is `uv-relay`. They share the transport —
//! above all the filename allow-list, whose whole job is to stop a stranger's
//! name being used as a path. Two copies of that would be two things to keep in
//! step, and the cost of them drifting is a path traversal.

pub mod fees;
pub mod transport;
