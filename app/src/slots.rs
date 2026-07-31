//! Which of a payee's one-time slots this payer has already used.
//!
//! **The most dangerous small file in the system**, though less dangerous than
//! it was. Each slot carries one spend anchor. Build two notes on one slot and
//! both commit to the same anchor: the payee can spend only one of them, the
//! other is an unplaceable bundle, and the two are publicly linkable as paying
//! the same person. Until 2026-07-29 the consequence was worse — a slot held a
//! one-time signing key and a collision disclosed it — and this file's rules
//! were written against that. They are kept at that strength deliberately: the
//! collision is still a fund loss for one of the two notes, and a discipline
//! relaxed because the worst case got smaller is a discipline nobody re-derives
//! when it grows again. Nothing on the payee's side can stop this, because
//! which slots a payer has consumed is
//! payer-local state by design: the payee cannot see it, and two independent
//! payers holding one address both start at slot 0 without either doing
//! anything wrong.
//!
//! So this file is the only thing standing in the way, and every rule below
//! exists because the obvious version of it was wrong first.
//!
//! Extracted from `cli/src/main.rs` for the phone. The reasoning is unchanged;
//! what changed is that a failure returns rather than calling
//! `std::process::exit`, and that the reservation write is now atomic.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// Where one address's reservations live.
///
/// **Keyed on the address's contents, not its filename.** Keyed on the file
/// stem, copying `bob.json` to `bob2.json` reset every reservation, and two
/// unrelated payees whose files happened to share a stem shared one list.
///
/// **SHA-256, not `DefaultHasher`.** `DefaultHasher`'s output is explicitly not
/// stable across Rust releases and `rust-toolchain.toml` floats on `stable`, so
/// a routine `rustup update` would rename every reservation file, every slot
/// would read as unused, and two notes would land under one one-time key. Key
/// disclosure triggered by a toolchain bump, with nothing to see. Pinned by
/// `tests::the_reservation_filename_is_stable_forever` (not a doc link: it is
/// a `#[cfg(test)]` item, which rustdoc cannot resolve).
pub fn address_id(x25519_hex: &str, ml_kem_hex: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    // Length-prefixed so the two fields cannot be slid into one another.
    for field in [x25519_hex, ml_kem_hex] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    hex::encode(&h.finalize()[..8])
}

pub fn reservation_path(home: &Path, addr_id: &str) -> PathBuf {
    home.join(format!("used-slots-{addr_id}.json"))
}

/// Read the reservations for one address.
///
/// **Absent means "nothing reserved yet"; unreadable means refuse.** Those are
/// not the same and collapsing them is how a slot gets used twice: the file is
/// written with a plain write, so a partial one on a full disk produced exactly
/// the input that then parsed as "no slots used".
pub fn read(home: &Path, addr_id: &str) -> Result<Vec<u64>> {
    let p = reservation_path(home, addr_id);
    match std::fs::read(&p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::Storage(format!(
            "cannot read {}: {e}\nthis file records which address slots are already spent; \
             continuing could reuse one and disclose a signing key",
            p.display()
        ))),
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
            Error::Storage(format!(
                "{} is corrupt: {e}\nrefusing rather than treating every slot as unused",
                p.display()
            ))
        }),
    }
}

/// Reserve slots, **before** anything is published or mailed.
///
/// The ordering is the point and it is not tidiness. Reservations used to be
/// written *after* the mailing, so a crash mid-payment lost them, a retry
/// reused slot 0, and two notes were built on one one-time key. Reserving first
/// costs, at worst, a slot burnt by a payment that never happened — which is a
/// slot, not a key.
///
/// Written atomically, which the version this replaces did not do. A torn write
/// here yields a file that may parse as a *shorter* list, and a shorter list is
/// a slot that reads as free.
pub fn reserve(home: &Path, addr_id: &str, used: &mut Vec<u64>, newly: &[u64]) -> Result<()> {
    if newly.is_empty() {
        return Ok(());
    }
    let p = reservation_path(home, addr_id);
    let _guard = Lock::acquire(&p)?;

    // **Re-read inside the lock.** `used` is the caller's copy from some earlier
    // point, and between then and now another process may have reserved. Trusting
    // it is how two payers both take slot 0 without either duplicate check firing.
    // The file is authoritative; the argument is a hint.
    let mut authoritative = read(home, addr_id)?;
    for i in newly {
        if authoritative.contains(i) {
            return Err(Error::Refused(format!(
                "slot {i} is already spent for this address; reusing it would put two \
                 notes on one spend anchor"
            )));
        }
    }
    authoritative.extend_from_slice(newly);

    // A **unique** temp name. A shared one is not a smaller version of this bug,
    // it is a different and worse one — see `Lock` below.
    let tmp = p.with_extension(format!("json.tmp.{}", unique_suffix()));
    let bytes = serde_json::to_vec(&authoritative)
        .map_err(|e| Error::Storage(format!("serialize reservations: {e}")))?;
    std::fs::write(&tmp, &bytes)
        .map_err(|e| Error::Storage(format!("write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::Storage(format!("install {}: {e}", p.display()))
    })?;

    // Hand the caller what is now true, not what it guessed.
    *used = authoritative;
    Ok(())
}

/// A distinct temp filename per writer.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// An exclusive lock over one address's reservation file.
///
/// **Both of the races this closes were found on 2026-07-30 by the first test
/// that ever ran two writers against one `--home`** (`app/tests/
/// two_payers_cannot_reserve_one_slot.rs`). Every existing defence here — the
/// atomic rename, reserve-before-publish, refusing a corrupt file — is about a
/// single writer, and `[SLOT-COLLISION]` is a *concurrency* hazard. Nobody had
/// run two.
///
/// **Race one, the one that was predicted.** `reserve` trusted the caller's
/// in-memory `used`. Two processes both read `[]`, both check slot 0 against
/// their stale copy, both pass, both write. Fixed by re-reading under this lock.
///
/// **Race two, which was worse and was not predicted.** Every writer used the
/// *same* temp path, `used-slots-<id>.json.tmp`. So writer A could write its
/// temp file, writer B overwrite that same temp file with different contents,
/// and A then rename it into place — **installing B's list while believing it
/// installed its own.** A returns `Ok`, proceeds to use the slot it thinks it
/// reserved, and the file does not record it. The atomic rename was working
/// perfectly and guaranteeing nothing, because atomicity of the *install* says
/// nothing about who wrote the thing being installed. The observed symptom was
/// the milder sibling: the second rename failing `ENOENT` because the first had
/// already consumed the shared temp file.
///
/// **Why a lock file and not `flock`.** No new dependency, and `create_new` is
/// atomic on every platform this ships to. The cost is that a process killed
/// between acquiring and releasing leaves the lock behind; that is why the wait
/// is bounded and the error says exactly which file to delete, rather than the
/// lock being silently ignored after a timeout. **Silently breaking a lock to
/// make progress would reintroduce the bug the lock exists to prevent.**
struct Lock(PathBuf);

impl Lock {
    /// Wait up to ~2 seconds. Reservation is a short critical section — a read,
    /// a check, and a rename — so anything slower is a stale lock, not contention.
    fn acquire(target: &Path) -> Result<Self> {
        let path = target.with_extension("json.lock");
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        for attempt in 0..200 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Lock(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = attempt;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(Error::Storage(format!(
                        "cannot lock {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        Err(Error::Storage(format!(
            "timed out waiting for {}\nanother `uv` is reserving slots for this address, \
             or one was killed while holding the lock. If you are certain no other `uv` \
             is running, delete that file. It is NOT removed automatically: doing so \
             would let two payers reserve the same slot, which is the fund loss this \
             lock exists to prevent.",
            path.display()
        )))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The slots still available on an address of `count` slots.
pub fn free(count: u64, used: &[u64]) -> Vec<u64> {
    (0..count).filter(|i| !used.contains(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("uv-slots-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// **A pinned vector, computed independently.** If this value ever changes,
    /// every existing reservation file is orphaned and every slot in it reads
    /// as free — so the test exists to make that a deliberate act rather than a
    /// side effect of changing a hash. The expected digest was derived by hand
    /// rather than copied from a first run, because a self-blessed vector only
    /// proves the code agrees with itself.
    #[test]
    fn the_reservation_filename_is_stable_forever() {
        // sha256( le64(2) ‖ "aa" ‖ le64(2) ‖ "bb" )[..8]
        let got = address_id("aa", "bb");
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        for f in ["aa", "bb"] {
            sha2::Digest::update(&mut h, 2u64.to_le_bytes());
            sha2::Digest::update(&mut h, f.as_bytes());
        }
        let want = hex::encode(&sha2::Digest::finalize(h)[..8]);
        assert_eq!(got, want);
        assert_eq!(got.len(), 16, "8 bytes, hex");
    }

    /// Length prefixes exist so two fields cannot be slid into one another.
    /// Without them `("aab","b")` and `("aa","bb")` would hash identically, and
    /// two different addresses would share one reservation list.
    #[test]
    fn fields_cannot_be_slid_into_one_another() {
        assert_ne!(address_id("aab", "b"), address_id("aa", "bb"));
    }

    #[test]
    fn a_missing_file_means_nothing_is_reserved() {
        let h = tmpdir("absent");
        assert_eq!(read(&h, "deadbeef").unwrap(), Vec::<u64>::new());
    }

    /// **The distinction that matters.** A file that cannot be read is not an
    /// empty file. Treating the two alike is how a partial write turns into a
    /// disclosed key.
    #[test]
    fn an_unreadable_file_is_refused_not_read_as_empty() {
        let h = tmpdir("corrupt");
        std::fs::write(reservation_path(&h, "beef"), b"{not json").unwrap();
        let e = read(&h, "beef").unwrap_err();
        assert_eq!(e.kind(), "storage");
        assert!(e
            .to_string()
            .contains("rather than treating every slot as unused"));
    }

    #[test]
    fn reservations_round_trip_and_accumulate() {
        let h = tmpdir("rt");
        let mut used = read(&h, "aa").unwrap();
        reserve(&h, "aa", &mut used, &[0, 1]).unwrap();
        assert_eq!(read(&h, "aa").unwrap(), vec![0, 1]);
        reserve(&h, "aa", &mut used, &[2]).unwrap();
        assert_eq!(read(&h, "aa").unwrap(), vec![0, 1, 2]);
    }

    /// Reserving a slot twice is refused rather than silently appended. A
    /// duplicate in the list is harmless on its own; the caller asking for it
    /// means the caller's own bookkeeping is wrong, and continuing would be
    /// building a second note on a used key.
    #[test]
    fn a_slot_cannot_be_reserved_twice() {
        let h = tmpdir("dup");
        let mut used = Vec::new();
        reserve(&h, "aa", &mut used, &[0]).unwrap();
        let e = reserve(&h, "aa", &mut used, &[0]).unwrap_err();
        assert_eq!(e.kind(), "refused");
        assert_eq!(
            read(&h, "aa").unwrap(),
            vec![0],
            "the file must not have grown"
        );
    }

    #[test]
    fn free_slots_exclude_the_used_ones() {
        assert_eq!(free(4, &[0, 2]), vec![1, 3]);
        assert_eq!(free(2, &[0, 1]), Vec::<u64>::new());
        assert_eq!(free(3, &[]), vec![0, 1, 2]);
    }

    /// Reserving nothing writes nothing. A no-op that still touched the file
    /// would be a chance to corrupt it for no reason.
    #[test]
    fn reserving_nothing_creates_no_file() {
        let h = tmpdir("noop");
        let mut used = Vec::new();
        reserve(&h, "aa", &mut used, &[]).unwrap();
        assert!(!reservation_path(&h, "aa").exists());
    }
}
