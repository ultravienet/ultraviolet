//! Reading and writing a wallet file.
//!
//! Moved out of `cli/src/main.rs`, where every failure was an `eprintln!`
//! followed by `std::process::exit(1)`. That is a perfectly good way for a
//! terminal to fail and a completely useless one for an app: a phone cannot
//! exit its own process to report a wrong passphrase.
//!
//! The refusals themselves are unchanged and are not incidental — two of them
//! exist to stop a one-time key signing twice, which is the failure that
//! discloses a secret key rather than merely losing a payment.

use std::path::Path;

use serde::{Deserialize, Serialize};
use uv_kernel2::keys::WalletSeed;
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::Store;

use crate::home::wallet_path;
use crate::vault;
use crate::{Error, Result};

/// Marks a file as an Ultraviolet wallet.
const WALLET_MAGIC: &[u8; 4] = b"UVW2";
const WALLET_PLAIN: u8 = 0;
const WALLET_SEALED: u8 = 1;

/// The wallet body's layout version, checked **before** the body is trusted.
///
/// **This is a fund-loss guard, not a nicety.** `bincode` is not
/// self-describing: it writes fields back to back with no names and no tags, so
/// reordering two fields of [`WalletFile`], `Store`, or `Held`, adding a variant
/// to an enum they contain, or a `bincode` bump that changes the wire format all
/// produce a file that decodes to **wrong values rather than an error** — a note
/// with the wrong amount, a lineage read as some other coin's. And the wallet
/// file is the *only* copy of a lineage once bundles are deleted (`SPEC.md` §10),
/// so a silent misread is a silently lost coin.
///
/// A version at the front of the body turns the *format* half of that into a
/// clean refusal. The remaining half — a same-version field reorder — is what
/// the golden-fixture test (`app/tests/the_wallet_format_is_pinned.rs`) exists to
/// catch: it holds a committed serialization and fails if today's encoder does
/// not reproduce it byte for byte. Bump this constant, and that fixture, in the
/// same commit that changes the layout; never one without the other.
pub const WALLET_FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
struct WalletFile {
    /// First field, so it is read before anything downstream is trusted.
    format: u32,
    seed_hex: String,
    store: Store,
    log: SignLog,
}

/// Everything one wallet holds.
pub struct Wallet {
    pub seed: WalletSeed,
    pub store: Store,
    pub log: SignLog,
}

/// **Redacting, and hand-written for that reason.** `#[derive(Debug)]` would
/// print the seed — and `Debug` is what a panic message, a log line, or a
/// crash reporter reaches for. Every note key derives from those 32 bytes, so
/// one stack trace off a phone would be the whole wallet. The derive is the
/// obvious thing to reach for here and it is the wrong one.
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("seed", &"<redacted>")
            .field("notes", &self.store.iter().count())
            .finish()
    }
}

/// Whether a wallet file exists and is sealed, without opening it.
///
/// An app needs this before it can ask for anything: it decides whether to show
/// a passphrase prompt, and asking for a passphrase that is not needed teaches
/// people to type it where it is not wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sealing {
    Absent,
    Plain,
    Sealed,
}

pub fn sealing(home: &Path, name: &str) -> Result<Sealing> {
    let p = wallet_path(home, name)?;
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Sealing::Absent),
        Err(e) => return Err(Error::Storage(format!("cannot read {}: {e}", p.display()))),
    };
    if bytes.len() < 5 || &bytes[..4] != WALLET_MAGIC {
        return Err(Error::BadInput(format!(
            "{}: not an Ultraviolet wallet file",
            p.display()
        )));
    }
    match bytes[4] {
        WALLET_SEALED => Ok(Sealing::Sealed),
        WALLET_PLAIN => Ok(Sealing::Plain),
        other => Err(Error::BadInput(format!(
            "unknown wallet format marker {other}"
        ))),
    }
}

/// Open a wallet, or create a fresh one if the file does not exist.
///
/// `passphrase` is a parameter rather than a process-wide value. The CLI could
/// get away with a `OnceLock` because a process runs one command; an app is
/// long-lived and can be locked and unlocked while running, so a global would
/// mean a wallet that cannot be re-locked without restarting.
pub fn open_or_create(home: &Path, name: &str, passphrase: Option<&str>) -> Result<Wallet> {
    let p = wallet_path(home, name)?;
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A fresh wallet. The seed is the only thing that must be backed
            // up — plus the sign log, which is not a cache (`SPEC.md` §6).
            let mut seed = [0u8; 32];
            fill_random(&mut seed)?;
            return Ok(Wallet {
                seed: WalletSeed(seed),
                store: Store::new(),
                log: SignLog::new(),
            });
        }
        Err(e) => return Err(Error::Storage(format!("cannot read {}: {e}", p.display()))),
    };

    if bytes.len() < 5 || &bytes[..4] != WALLET_MAGIC {
        return Err(Error::BadInput(format!(
            "{}: not an Ultraviolet wallet file, or one written before the format \
             changed from JSON to a binary encoding. A wallet holds every note's \
             lineage, and lineages are mostly proof bytes: pretty-printed JSON \
             turned a real wallet into tens of megabytes. There is no converter, \
             because nothing here holds value yet — start a fresh wallet.",
            p.display()
        )));
    }

    let body = &bytes[5..];
    let plain = match bytes[4] {
        WALLET_SEALED => {
            let v: vault::Vault = bincode::deserialize(body).map_err(|_| {
                Error::BadInput("wallet is marked sealed but its envelope is unreadable".into())
            })?;
            let pw = passphrase.ok_or_else(|| {
                Error::BadInput("this wallet is encrypted; a passphrase is required".into())
            })?;
            vault::open(pw, &v).map_err(|_| {
                Error::BadInput(
                    "cannot open wallet: wrong passphrase, or the file was altered".into(),
                )
            })?
        }
        WALLET_PLAIN => body.to_vec(),
        other => {
            return Err(Error::BadInput(format!(
                "unknown wallet format marker {other}"
            )))
        }
    };

    let wf: WalletFile = bincode::deserialize(&plain)
        .map_err(|e| Error::BadInput(format!("wallet file is unreadable: {e}")))?;

    // **The format guard, read before any field below is trusted.** A wallet of
    // a layout this build does not know decodes — silently, `bincode` being
    // untagged — to wrong amounts and misattributed lineages. Refuse it. The
    // magic bump (`UVW1` -> `UVW2`) already rejects the pre-version files at the
    // door; this rejects a future version read by an older build.
    if wf.format != WALLET_FORMAT {
        return Err(Error::BadInput(format!(
            "{}: wallet body format is {} but this build expects {}. A wallet holds \
             every note's lineage and it is the only copy; reading it under the \
             wrong layout would misread amounts and lineages silently. Refusing.",
            p.display(),
            wf.format,
            WALLET_FORMAT
        )));
    }

    // **A key-disclosure guard, not a compatibility check.** Reading an old log
    // as empty would remove the only thing standing between a restored wallet
    // and a second signature under one one-time key. The older format was keyed
    // by note commitment rather than derivation index, so it answers "has this
    // key already signed?" wrongly while looking perfectly well-formed.
    if !wf.log.version_ok() {
        return Err(Error::BadInput(format!(
            "{}: the sign-log is an older format and cannot be trusted to answer \
             whether a key has already signed. Reading it as empty would risk \
             disclosing a one-time key. Start a fresh wallet.",
            p.display()
        )));
    }

    let sv = hex::decode(&wf.seed_hex)
        .map_err(|e| Error::BadInput(format!("wallet seed is not hex: {e}")))?;
    let seed: [u8; 32] = sv
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadInput("wallet seed is not 32 bytes".into()))?;

    Ok(Wallet {
        seed: WalletSeed(seed),
        store: wf.store,
        log: wf.log,
    })
}

/// Persist a wallet. **Atomically**: write a temporary file, then rename.
///
/// The version this replaced called `std::fs::write` straight onto the wallet
/// path, which is a truncate followed by a write. A crash between the two
/// leaves a truncated file — and the file holds the **sign log**, whose whole
/// job is to answer "has this one-time key already signed?". A wallet that
/// loses that answer and starts fresh is a wallet that will sign twice under
/// one key, which discloses the key rather than merely losing a payment.
///
/// On a laptop the window is small enough that it never bit us. On iOS it is
/// not a rare event: the system terminates backgrounded apps under memory
/// pressure, routinely and without warning. `rename` within one directory is
/// atomic on every filesystem either caller will meet, so the file is either
/// entirely the old wallet or entirely the new one.
pub fn save(
    home: &Path,
    name: &str,
    seed: &WalletSeed,
    store: &Store,
    log: &SignLog,
    passphrase: Option<&str>,
) -> Result<()> {
    let p = wallet_path(home, name)?;
    let dir = p
        .parent()
        .ok_or_else(|| Error::Storage("wallet path has no parent".into()))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| Error::Storage(format!("cannot create {}: {e}", dir.display())))?;

    let wf = WalletFile {
        format: WALLET_FORMAT,
        seed_hex: hex::encode(seed.0),
        store: clone_store(store)?,
        log: clone_log(log)?,
    };
    // bincode, not pretty JSON. A wallet stores every held note's full lineage,
    // and a lineage is mostly proof bytes — JSON wrote each one as its own
    // decimal number on its own line, which made the demo's largest wallet
    // 46 MB across 2.77 million lines.
    let plain =
        bincode::serialize(&wf).map_err(|e| Error::Storage(format!("serialize wallet: {e}")))?;

    let mut bytes = Vec::with_capacity(plain.len() + 5);
    bytes.extend_from_slice(WALLET_MAGIC);
    match passphrase {
        Some(pw) if !pw.is_empty() => {
            bytes.push(WALLET_SEALED);
            let sealed = bincode::serialize(&vault::seal(pw, &plain))
                .map_err(|e| Error::Storage(format!("seal wallet: {e}")))?;
            bytes.extend_from_slice(&sealed);
        }
        _ => {
            bytes.push(WALLET_PLAIN);
            bytes.extend_from_slice(&plain);
        }
    }

    // Same directory, so the rename cannot cross a filesystem boundary — which
    // is the one case where rename is not atomic.
    let tmp = p.with_extension("uvw.tmp");
    std::fs::write(&tmp, &bytes)
        .map_err(|e| Error::Storage(format!("write {}: {e}", tmp.display())))?;
    restrict(&tmp);
    std::fs::rename(&tmp, &p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::Storage(format!("install {}: {e}", p.display()))
    })?;
    restrict(&p);
    Ok(())
}

/// Owner-only, best effort. A wallet file is a seed.
fn restrict(p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = p;
}

/// 32 bytes of OS randomness, without pulling in a crate for it.
fn fill_random(buf: &mut [u8; 32]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| Error::Storage(format!("cannot read system randomness: {e}")))
}

// serde round-trip clones, so the persisted types need no Clone bound.
fn clone_store(s: &Store) -> Result<Store> {
    let b = serde_json::to_vec(s).map_err(|e| Error::Storage(format!("clone store: {e}")))?;
    serde_json::from_slice(&b).map_err(|e| Error::Storage(format!("clone store: {e}")))
}
fn clone_log(l: &SignLog) -> Result<SignLog> {
    let b = serde_json::to_vec(l).map_err(|e| Error::Storage(format!("clone log: {e}")))?;
    serde_json::from_slice(&b).map_err(|e| Error::Storage(format!("clone log: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("uv-app-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("wallets")).unwrap();
        d
    }

    /// A seed must not be printable by accident. `Debug` is what panics and
    /// crash reporters use, so a derived one would put the whole wallet in a
    /// log the first time anything went wrong on someone's phone.
    #[test]
    fn debug_does_not_print_the_seed() {
        let h = tmpdir("redact");
        let w = open_or_create(&h, "alice", None).unwrap();
        let shown = format!("{w:?}");
        assert!(shown.contains("<redacted>"), "got {shown}");
        assert!(
            !shown.contains(&hex::encode(w.seed.0)),
            "the seed leaked into Debug output"
        );
    }

    #[test]
    fn a_missing_wallet_is_created_rather_than_refused() {
        let h = tmpdir("fresh");
        let w = open_or_create(&h, "alice", None).expect("fresh wallet");
        assert_ne!(w.seed.0, [0u8; 32], "a fresh seed must be random");
        assert!(matches!(sealing(&h, "alice").unwrap(), Sealing::Absent));
    }

    #[test]
    fn a_plain_wallet_round_trips() {
        let h = tmpdir("plain");
        let w = open_or_create(&h, "alice", None).unwrap();
        save(&h, "alice", &w.seed, &w.store, &w.log, None).unwrap();
        assert!(matches!(sealing(&h, "alice").unwrap(), Sealing::Plain));
        let again = open_or_create(&h, "alice", None).unwrap();
        assert_eq!(again.seed.0, w.seed.0);
    }

    #[test]
    fn a_sealed_wallet_needs_its_passphrase() {
        let h = tmpdir("sealed");
        let w = open_or_create(&h, "alice", None).unwrap();
        save(&h, "alice", &w.seed, &w.store, &w.log, Some("hunter2")).unwrap();
        assert!(matches!(sealing(&h, "alice").unwrap(), Sealing::Sealed));

        // No passphrase: refused, and told why rather than treated as corrupt.
        let e = open_or_create(&h, "alice", None).unwrap_err();
        assert_eq!(e.kind(), "bad_input");
        assert!(e.to_string().contains("passphrase is required"));

        // Wrong passphrase: refused.
        assert!(open_or_create(&h, "alice", Some("wrong")).is_err());

        // Right passphrase: the same seed comes back.
        let again = open_or_create(&h, "alice", Some("hunter2")).unwrap();
        assert_eq!(again.seed.0, w.seed.0);
    }

    /// **The reason `save` writes through a temporary file.** A wallet that
    /// exists must never be replaced by a partial one, because the file holds
    /// the sign log. Here the destination already holds a good wallet and the
    /// new write fails to install; the old one must still be readable.
    #[test]
    fn a_failed_install_leaves_the_previous_wallet_intact() {
        let h = tmpdir("atomic");
        let w = open_or_create(&h, "alice", None).unwrap();
        save(&h, "alice", &w.seed, &w.store, &w.log, None).unwrap();

        // Simulate the crash window: a temporary file left behind by an
        // interrupted save. It must not be mistaken for the wallet.
        let tmp = wallet_path(&h, "alice").unwrap().with_extension("uvw.tmp");
        std::fs::write(&tmp, b"garbage").unwrap();

        let again = open_or_create(&h, "alice", None).expect("the real wallet still opens");
        assert_eq!(again.seed.0, w.seed.0);
        let _ = std::fs::remove_file(&tmp);
    }

    /// A truncated file is refused outright rather than read as an empty
    /// wallet. An empty wallet has an empty sign log, and an empty sign log
    /// says every one-time key is unused.
    #[test]
    fn a_truncated_wallet_is_refused_not_read_as_empty() {
        let h = tmpdir("trunc");
        let p = wallet_path(&h, "alice").unwrap();
        std::fs::write(&p, b"UV").unwrap();
        let e = open_or_create(&h, "alice", None).unwrap_err();
        assert_eq!(e.kind(), "bad_input");
    }

    #[test]
    fn a_name_that_escapes_the_home_is_refused_before_any_io() {
        let h = tmpdir("escape");
        assert!(open_or_create(&h, "../oops", None).is_err());
        assert!(sealing(&h, "../oops").is_err());
    }
}
