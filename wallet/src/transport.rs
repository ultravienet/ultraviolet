//! The transport abstraction: deliver an encrypted bundle to a recipient's
//! mailbox and let them scan for bundles addressed to them. Nostr is one impl
//! (`uv-nostr`); the `FileTransport` here uses a shared directory so the whole
//! POC runs with no network.

use std::fs;
use std::path::{Path, PathBuf};

/// A posted, encrypted bundle plus the scan tag it was filed under.
pub struct Delivered {
    pub tag: String,
    pub ciphertext: Vec<u8>,
}

/// A mailbox: post an encrypted bundle under a scan tag; fetch everything under
/// a tag. The recipient trial-decrypts what it fetches (envelope::open).
pub trait Transport {
    fn post(&self, tag: &str, ciphertext: &[u8]);
    fn fetch(&self, tag: &str) -> Vec<Delivered>;
}

/// Filesystem mailbox: one file per posted bundle under `<root>/<tag>/`.
pub struct FileTransport {
    root: PathBuf,
}

impl FileTransport {
    pub fn new(root: impl AsRef<Path>) -> Self {
        FileTransport { root: root.as_ref().to_path_buf() }
    }
}

impl Transport for FileTransport {
    fn post(&self, tag: &str, ciphertext: &[u8]) {
        let dir = self.root.join(tag);
        fs::create_dir_all(&dir).expect("create mailbox dir");
        // Content-addressed filename so re-posts dedupe and ordering is stable.
        let name = hex::encode(&sha2_256(ciphertext)[..8]);
        fs::write(dir.join(format!("{name}.bundle")), ciphertext).expect("write bundle");
    }

    fn fetch(&self, tag: &str) -> Vec<Delivered> {
        let dir = self.root.join(tag);
        let Ok(entries) = fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut names: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        names
            .into_iter()
            .filter_map(|p| fs::read(&p).ok().map(|ct| Delivered { tag: tag.to_string(), ciphertext: ct }))
            .collect()
    }
}

fn sha2_256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_then_fetch() {
        let dir = tempfile::tempdir().unwrap();
        let t = FileTransport::new(dir.path());
        t.post("bob-scan-tag", b"ciphertext-1");
        t.post("bob-scan-tag", b"ciphertext-2");
        let got: Vec<_> = t.fetch("bob-scan-tag").into_iter().map(|d| d.ciphertext).collect();
        assert_eq!(got.len(), 2);
        assert!(t.fetch("nobody").is_empty());
    }
}
