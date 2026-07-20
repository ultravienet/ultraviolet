//! # uv-wallet
//!
//! The Ultraviolet wallet core: identities, notes, addresses, the hybrid
//! ML-KEM note envelope, and the `Chain` / `Transport` abstractions with
//! in-process mocks. Deliberately free of any zkVM dependency — proofs are
//! carried as opaque bytes and produced/verified by `uv-prove` — so this
//! crate's tests stay fast.

pub mod bundle;
pub mod chain;
pub mod envelope;
pub mod keys;
pub mod note;
pub mod transport;

pub use bundle::Bundle;
pub use chain::{Chain, FileChain, MockChain, RecordLoc};
pub use keys::{parse_address, scan_tag_for, Identity, Recipient};
pub use note::{NoteStore, OwnedNote};
pub use transport::{FileTransport, Transport};
