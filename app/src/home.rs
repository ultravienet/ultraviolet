//! Where a home's files live.
//!
//! A "home" is one directory holding a set of wallets, the trust anchor, the
//! chain view, and the mailbox. The CLI takes it from `--home`; the phone has
//! exactly one, inside the app container.
//!
//! These are the only paths either caller may construct. Two reasons, and the
//! second is the one that matters: an app sandbox has no `~`, no CWD worth
//! speaking of, and a container path that changes between installs — so a
//! caller that builds its own paths is a caller that works on a laptop and
//! silently loses a wallet on a phone. And a wallet name reaches these
//! functions from outside, so exactly one place should decide what a name may
//! contain.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The file holding one named wallet.
pub fn wallet_path(home: &Path, name: &str) -> Result<PathBuf> {
    Ok(home
        .join("wallets")
        .join(format!("{}.uvw", safe_name(name)?)))
}

/// The trust anchor. One per home: a home holds one asset.
pub fn anchor_path(home: &Path) -> PathBuf {
    home.join("anchor.json")
}

/// The file-backed chain view, for the mock and file backends.
pub fn chain_path(home: &Path) -> PathBuf {
    home.join("chain.json")
}

/// Where sealed bundles arrive.
pub fn inbox_dir(home: &Path) -> PathBuf {
    home.join("mailbox").join("inbox")
}

/// Bundles that were real but had nowhere to land — kept, never deleted.
pub fn unplaceable_dir(home: &Path) -> PathBuf {
    home.join("mailbox").join("unplaceable")
}

/// A wallet name that is safe to use as a filename.
///
/// **This is a path-traversal check, not tidiness.** A name arrives from a
/// human on the CLI and from a text field on a phone, and both end up in
/// `home/wallets/<name>.uvw`. A name of `../../anchor` would write outside the
/// home; on iOS, outside the app's own container.
///
/// Allow-list rather than deny-list, and deliberately narrow: letters, digits,
/// `-` and `_`. `cli::transport::safe_name` makes the same choice for peer
/// names, for the same reason — a deny-list is a list of the traversals someone
/// thought of.
pub fn safe_name(name: &str) -> Result<&str> {
    if name.is_empty() {
        return Err(Error::BadInput("a wallet name cannot be empty".into()));
    }
    if name.len() > 64 {
        return Err(Error::BadInput(format!(
            "wallet name is {} characters; the limit is 64",
            name.len()
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::BadInput(format!(
            "wallet name {name:?} may use only letters, digits, '-' and '_' — \
             it becomes a filename, and anything else is a way out of the home \
             directory"
        )));
    }
    Ok(name)
}

/// Create the directories a home needs, if they are missing.
///
/// Idempotent, and called before anything is written rather than at each write
/// site: a missing `mailbox/inbox` on a fresh install would otherwise surface
/// as a scan that finds nothing, which reads as "no payments" rather than "no
/// directory".
pub fn ensure(home: &Path) -> Result<()> {
    for d in [home.join("wallets"), inbox_dir(home), unplaceable_dir(home)] {
        std::fs::create_dir_all(&d)
            .map_err(|e| Error::Storage(format!("cannot create {}: {e}", d.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_are_fine() {
        for n in ["alice", "bob-2", "cold_storage", "a", "A1"] {
            assert!(safe_name(n).is_ok(), "{n} should be allowed");
        }
    }

    /// **The reason this function exists.** Each of these would otherwise write
    /// outside the home — on a phone, outside the app's container.
    #[test]
    fn a_name_cannot_escape_the_home_directory() {
        for n in [
            "../anchor",
            "../../etc/passwd",
            "a/b",
            "a\\b",
            ".",
            "..",
            "with space",
            "semi;colon",
            "null\0byte",
        ] {
            let r = safe_name(n);
            assert!(r.is_err(), "{n:?} must be refused");
            assert_eq!(r.unwrap_err().kind(), "bad_input");
        }
    }

    #[test]
    fn empty_and_overlong_names_are_refused() {
        assert!(safe_name("").is_err());
        assert!(safe_name(&"a".repeat(65)).is_err());
        assert!(
            safe_name(&"a".repeat(64)).is_ok(),
            "64 is the limit, inclusive"
        );
    }

    /// A refused name must not produce a path at all — the check belongs before
    /// the join, not after it.
    #[test]
    fn a_refused_name_yields_no_path() {
        assert!(wallet_path(Path::new("/tmp/home"), "../escape").is_err());
    }

    #[test]
    fn paths_sit_under_the_home() {
        let h = Path::new("/tmp/uvhome");
        assert_eq!(
            wallet_path(h, "alice").unwrap(),
            Path::new("/tmp/uvhome/wallets/alice.uvw")
        );
        assert_eq!(anchor_path(h), Path::new("/tmp/uvhome/anchor.json"));
        assert_eq!(inbox_dir(h), Path::new("/tmp/uvhome/mailbox/inbox"));
    }
}
