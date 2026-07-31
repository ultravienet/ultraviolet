//! An unreadable chain file used to answer every question with "no".
//!
//! **The bug.** `FileChain::open` was
//! `read().ok().and_then(parse).unwrap_or_default()`. Every failure — a
//! truncated write, a permissions problem, a file half-written when the process
//! died, a JSON schema change — collapsed to `FileState::default()`: no records,
//! tip 0. In a chain with no records, **every nullifier is unspent.** A wallet
//! consulting that view accepts coins that were already spent, and nothing looks
//! wrong: no error, no warning, a plausible-looking empty chain.
//!
//! It is the fail-open that `slots.rs` and `index.rs` each explicitly refuse to
//! commit, in a comment, committed here — in the backend the iOS app uses by
//! default.
//!
//! **The distinction that makes the fix safe.** *Absent* is not *corrupt*. No
//! file means a fresh wallet, and an empty chain is the honest answer there; a
//! file that exists and will not parse is a question we cannot answer, so we
//! refuse to answer it. Both halves are tested here, because a fix that
//! refused the missing-file case too would break every fresh wallet and would
//! have been "caught" by a test that only checked corruption.

use std::io::Write;

use uv_wallet2::chain::{Chain, ChainOpenError, FileChain};

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "uv-chain-test-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    let mut f = std::fs::File::create(path).expect("create");
    f.write_all(bytes).expect("write");
}

/// Garbage is refused rather than read as an empty chain.
#[test]
fn a_file_that_is_not_json_is_refused() {
    let dir = tmpdir();
    let p = dir.join("garbage-chain.json");
    write(&p, b"this is not json");

    match FileChain::open(&p) {
        Err(ChainOpenError::Corrupt(_)) => {}
        Err(other) => panic!("expected Corrupt, got {other:?}"),
        Ok(_) => panic!(
            "a corrupt chain file was read as a chain — if it parsed as empty, every \
             nullifier in it reads as unspent and the wallet accepts spent coins"
        ),
    }
    let _ = std::fs::remove_file(&p);
}

/// A truncated file — the realistic corruption, from a write interrupted midway.
#[test]
fn a_truncated_file_is_refused() {
    let dir = tmpdir();
    let p = dir.join("truncated-chain.json");
    // Valid JSON prefix, cut off. This is what a killed process leaves behind.
    write(&p, br#"{"records":[],"issuances":[],"ti"#);

    assert!(
        matches!(FileChain::open(&p), Err(ChainOpenError::Corrupt(_))),
        "a half-written chain file must be refused, not defaulted"
    );
    let _ = std::fs::remove_file(&p);
}

/// Valid JSON of the wrong shape is still not a chain.
#[test]
fn valid_json_that_is_not_a_chain_is_refused() {
    let dir = tmpdir();
    let p = dir.join("wrong-shape-chain.json");
    write(&p, br#"{"something":"else"}"#);

    assert!(
        matches!(FileChain::open(&p), Err(ChainOpenError::Corrupt(_))),
        "JSON that parses but is not a chain must be refused"
    );
    let _ = std::fs::remove_file(&p);
}

/// **The other half.** A missing file is a fresh wallet, and must still work.
///
/// Without this, a fix that refused everything would pass every test above while
/// breaking the first run of every new wallet.
#[test]
fn a_missing_file_is_a_fresh_chain_not_an_error() {
    let dir = tmpdir();
    let p = dir.join("definitely-not-created-yet.json");
    let _ = std::fs::remove_file(&p);

    let chain = FileChain::open(&p).expect("a missing chain file is a fresh wallet, not an error");
    assert_eq!(
        chain.tip().expect("tip of a fresh chain"),
        0,
        "a fresh chain starts at tip 0"
    );
}

/// A chain we wrote ourselves reads back, so the refusals above are not
/// refusing everything.
#[test]
fn a_well_formed_file_still_opens() {
    let dir = tmpdir();
    let p = dir.join("good-chain.json");
    write(&p, br#"{"records":[],"issuances":[],"tip":7}"#);

    let chain = FileChain::open(&p).expect("a well-formed chain file must open");
    assert_eq!(
        chain.tip().expect("tip"),
        7,
        "the tip must survive the round trip"
    );
    let _ = std::fs::remove_file(&p);
}
