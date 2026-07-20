//! The chain abstraction: publish a 64-byte record, ask whether a nullifier's
//! first occurrence is a given record. Bitcoin is one impl (`uv-btc`); the
//! in-process `MockChain` here lets the whole POC run with no network.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use ultraviolet_kernel::hash::Hash256;
use ultraviolet_kernel::nullifier::Record;

/// Where a record landed, enough to order first-occurrence deterministically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordLoc {
    /// Opaque ordering position (block height, or mock sequence number).
    pub height: u64,
    /// Index within the position (tx/leaf index).
    pub index: u32,
    /// Confirmations at last query.
    pub confirmations: u64,
}

/// The chain: an append-only, first-occurrence-wins ledger of 64-byte records.
pub trait Chain {
    /// Publish a record. Idempotent per nullifier: if this nullifier already
    /// has a record, the existing one stands (first occurrence wins) and its
    /// location is returned.
    fn publish(&self, record: &Record) -> RecordLoc;

    /// The record and location of a nullifier's *first* occurrence, if any.
    fn first_occurrence(&self, nf: &Hash256) -> Option<(Record, RecordLoc)>;
}

/// Deterministic in-process chain for local runs and tests.
#[derive(Default)]
pub struct MockChain {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    /// nullifier → (record, first-occurrence location)
    first: HashMap<Hash256, (Record, RecordLoc)>,
    seq: u64,
}

impl MockChain {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Chain for MockChain {
    fn publish(&self, record: &Record) -> RecordLoc {
        let mut g = self.inner.lock().unwrap();
        if let Some((_, loc)) = g.first.get(&record.nf.0) {
            return *loc; // first occurrence wins; re-publish is a no-op
        }
        let loc = RecordLoc { height: g.seq, index: 0, confirmations: 1 };
        g.seq += 1;
        g.first.insert(record.nf.0, (*record, loc));
        loc
    }

    fn first_occurrence(&self, nf: &Hash256) -> Option<(Record, RecordLoc)> {
        self.inner.lock().unwrap().first.get(nf).copied()
    }
}

/// A file-backed chain: the same first-occurrence semantics as `MockChain`,
/// but persisted so it survives across separate CLI invocations (it stands in
/// for "the network" that all wallets share). Read-modify-write per op — fine
/// for the POC's sequential demo, not for concurrent use.
pub struct FileChain {
    path: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
struct FileState {
    /// hex(nf) → (hex(record bytes), location)
    first: HashMap<String, (String, RecordLoc)>,
    seq: u64,
}

impl FileChain {
    pub fn new(path: impl AsRef<Path>) -> Self {
        FileChain { path: path.as_ref().to_path_buf() }
    }

    fn load(&self) -> FileState {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, st: &FileState) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(st).expect("serialize chain"))
            .expect("write chain");
    }
}

impl Chain for FileChain {
    fn publish(&self, record: &Record) -> RecordLoc {
        let mut st = self.load();
        let key = hex::encode(record.nf.0);
        if let Some((_, loc)) = st.first.get(&key) {
            return *loc;
        }
        let loc = RecordLoc { height: st.seq, index: 0, confirmations: 1 };
        st.seq += 1;
        st.first.insert(key, (hex::encode(record.to_bytes()), loc));
        self.save(&st);
        loc
    }

    fn first_occurrence(&self, nf: &Hash256) -> Option<(Record, RecordLoc)> {
        let st = self.load();
        let (rhex, loc) = st.first.get(&hex::encode(nf))?;
        let bytes = hex::decode(rhex).ok()?;
        let arr: [u8; Record::SIZE] = bytes.try_into().ok()?;
        Some((Record::from_bytes(&arr), *loc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ultraviolet_kernel::nullifier::Nullifier;

    fn rec(nf: u8, bundle: u8) -> Record {
        Record { nf: Nullifier([nf; 32]), bundle_hash: [bundle; 32] }
    }

    #[test]
    fn first_occurrence_wins_and_is_stable() {
        let c = MockChain::new();
        let loc1 = c.publish(&rec(1, 10));
        // a conflicting second spend of the same note (same nf, different bundle)
        let loc2 = c.publish(&rec(1, 99));
        assert_eq!(loc1, loc2, "second publish of a nullifier is a no-op");
        let (found, _) = c.first_occurrence(&[1; 32]).unwrap();
        assert_eq!(found.bundle_hash, [10; 32], "the first bundle stands");
        assert!(c.first_occurrence(&[2; 32]).is_none());
    }

    #[test]
    fn file_chain_persists_first_occurrence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.json");
        {
            let c = FileChain::new(&path);
            c.publish(&rec(5, 50));
            c.publish(&rec(5, 88)); // conflicting second spend
        }
        // reopen: state survived
        let c = FileChain::new(&path);
        let (found, _) = c.first_occurrence(&[5; 32]).unwrap();
        assert_eq!(found.bundle_hash, [50; 32]);
    }
}
