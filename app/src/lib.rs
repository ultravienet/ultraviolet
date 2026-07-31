//! The command layer, shared by the `uv` CLI and the iOS app.
//!
//! ## Why this crate exists
//!
//! Every safety discipline this project has was learned the expensive way and
//! lives in the command layer, not in the kernel: refuse before reserving a
//! slot, write the wallet before publishing, replay the sign log rather than
//! signing twice, keep a bundle when the verdict is transient, re-check the
//! genesis after a reorg. Until now all of it sat in `cli/src/main.rs` as
//! private functions that print to stdout and call `std::process::exit`.
//!
//! **An FFI cannot call any of that.** So a phone app either reimplements it —
//! reintroducing every fund-loss bug at a new boundary — or the logic moves
//! somewhere both callers share. This is that somewhere.
//!
//! The rule for anything that moves here: it returns a [`Result`] and a value.
//! It does not print, and it does not exit. Presentation belongs to the caller,
//! because one caller is a terminal and the other is a phone.
//!
//! ## What this is not
//!
//! It is not a stable API. The CLI and the app are the only callers and they
//! move together.

use std::fmt;

pub mod address;
pub mod anchor;
pub mod batches;
pub mod bundle;
pub mod commands;
pub mod home;
pub mod slots;
pub mod vault;
pub mod wallet;

/// Why a command could not be carried out.
///
/// **Deliberately a small closed set.** The temptation at an FFI boundary is a
/// string, and a string is what turns a caller's error handling into substring
/// matching — which then silently stops working when a message is reworded.
/// Each variant carries a message for a human, and the variant itself is what a
/// caller branches on.
#[derive(Debug)]
pub enum Error {
    /// The wallet, anchor, or file named does not exist.
    NotFound(String),
    /// Input the caller supplied is malformed. Never retried by the caller.
    BadInput(String),
    /// The wallet's own state refuses this — insufficient balance, an exhausted
    /// address, a note already spent.
    Refused(String),
    /// The chain view could not answer. **Transient by nature**: a node that is
    /// down or behind says nothing about the money, so a caller should offer a
    /// retry rather than report a failure.
    ChainUnavailable(String),
    /// Reading or writing local state failed.
    Storage(String),
}

impl Error {
    /// Whether trying again later could plausibly succeed, with nothing else
    /// changing.
    ///
    /// Exposed because the phone needs it and a terminal does not: a CLI user
    /// reads the message and decides, while an app has to choose between a
    /// retry button and an error state without a human in the loop.
    pub fn is_transient(&self) -> bool {
        matches!(self, Error::ChainUnavailable(_))
    }

    /// A short, stable tag for the variant. This is what crosses the FFI, not
    /// the prose.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::NotFound(_) => "not_found",
            Error::BadInput(_) => "bad_input",
            Error::Refused(_) => "refused",
            Error::ChainUnavailable(_) => "chain_unavailable",
            Error::Storage(_) => "storage",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(m)
            | Error::BadInput(m)
            | Error::Refused(m)
            | Error::ChainUnavailable(m)
            | Error::Storage(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The one classification that has cost real money in this project, now at
    /// a second boundary. `wallet2::accept::Rejected::is_permanent` got this
    /// wrong by defaulting unnamed variants to permanent, and a permanent
    /// verdict is what makes a caller destroy a bundle. The match here is
    /// exhaustive so a new variant cannot inherit a default.
    #[test]
    fn only_an_unavailable_chain_is_worth_retrying() {
        assert!(Error::ChainUnavailable("node down".into()).is_transient());
        for e in [
            Error::NotFound("x".into()),
            Error::BadInput("x".into()),
            Error::Refused("x".into()),
            Error::Storage("x".into()),
        ] {
            assert!(!e.is_transient(), "{} must not invite a retry", e.kind());
        }
    }

    /// Tags are what a caller branches on, so they are part of the contract and
    /// changing one is a breaking change. Pinned so that is a deliberate act.
    #[test]
    fn the_tags_are_stable() {
        assert_eq!(Error::NotFound(String::new()).kind(), "not_found");
        assert_eq!(Error::BadInput(String::new()).kind(), "bad_input");
        assert_eq!(Error::Refused(String::new()).kind(), "refused");
        assert_eq!(
            Error::ChainUnavailable(String::new()).kind(),
            "chain_unavailable"
        );
        assert_eq!(Error::Storage(String::new()).kind(), "storage");
    }

    /// The message reaches a human unchanged. An app shows it in an alert, so
    /// a wrapper that mangled it would be a wrapper that hid the reason.
    #[test]
    fn the_message_survives() {
        let e = Error::Refused("every selected note had already been spent".into());
        assert_eq!(e.to_string(), "every selected note had already been spent");
    }
}
