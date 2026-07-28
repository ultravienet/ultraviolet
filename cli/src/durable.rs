//! Crash-safe local state: exclusive process locks and atomic durable writes.
//!
//! The wallet's sign log is part of the one-time-signature safety boundary.
//! "Write returned `Ok`" is not enough: the bytes must survive power loss
//! before a record can be published, and two processes must not both make a
//! decision from the same pre-write snapshot.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// An advisory exclusive lock held for the lifetime of this value.
///
/// Lock files are separate from the data they protect so replacing a data file
/// atomically never replaces the inode carrying the lock.
pub struct ExclusiveLock {
    file: File,
}

impl ExclusiveLock {
    pub fn acquire(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = private_open(path)?;
        file.lock_exclusive()?;
        Ok(Self { file })
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Replace `path` atomically, with the replacement durable before returning.
///
/// The temporary file lives beside the target, so `rename` is atomic. It is
/// created private before the first secret byte is written, synced before the
/// rename, and the directory is synced afterwards so the name itself survives
/// power loss.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    std::fs::create_dir_all(parent)?;

    let (temp_path, mut temp) = create_temp(path)?;
    let result = (|| {
        temp.write_all(bytes)?;
        temp.sync_all()?;
        drop(temp);
        std::fs::rename(&temp_path, path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result
}

fn create_temp(path: &Path) -> io::Result<(PathBuf, File)> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 file name"))?;
    for _ in 0..100 {
        let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let candidate =
            path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
        match private_create_new(&candidate) {
            Ok(file) => return Ok((candidate, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary file",
    ))
}

fn private_open(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_mode(&mut options);
    options.open(path)
}

fn private_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_mode(&mut options);
    options.open(path)
}

#[cfg(unix)]
fn set_private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_: &mut OpenOptions) {}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn atomic_replacement_never_exposes_a_partial_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        atomic_write(&path, b"old complete state").unwrap();
        atomic_write(&path, b"new complete state").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"new complete state");
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_private_when_the_final_name_appears() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet");
        atomic_write(&path, b"seed and sign log").unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn the_process_lock_covers_the_whole_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.lock");
        let first = ExclusiveLock::acquire(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let _second = ExclusiveLock::acquire(&path).unwrap();
            tx.send(()).unwrap();
        });

        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "a second process-equivalent lock holder entered the transaction"
        );
        drop(first);
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        waiter.join().unwrap();
    }
}
