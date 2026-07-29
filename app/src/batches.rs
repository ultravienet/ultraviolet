//! The batch ledger: which slot ranges were handed out, and to whom.
//!
//! A sidecar rather than a field in the wallet: the wallet is read with plain
//! `bincode`, which is not self-describing, so a new field there would panic on
//! every wallet that already exists. Shared here because the phone answers the
//! same replenishment question (`status` shows what was handed out) and hands
//! out addresses the same way.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// One batch of slots, and who it was handed to.
#[derive(Clone, Serialize, Deserialize)]
pub struct Batch {
    /// Free-text label for the counterparty. Not an identity — nothing
    /// authenticates it — just what the payee called them when handing it over.
    pub peer: Option<String>,
    pub first: u64,
    pub count: u64,
}

pub fn path(home: &Path, wallet: &str) -> PathBuf {
    home.join(format!("batches-{wallet}.json"))
}

/// The wallet's batch ledger. Absent or unreadable reads as empty — the ledger
/// is a courtesy record for the human, not consensus state, so a lost file
/// costs labels, never money.
pub fn read(home: &Path, wallet: &str) -> Vec<Batch> {
    std::fs::read(path(home, wallet))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Append one batch to the ledger.
pub fn append(home: &Path, wallet: &str, batch: Batch) -> Result<()> {
    let mut batches = read(home, wallet);
    batches.push(batch);
    let bytes = serde_json::to_vec_pretty(&batches)
        .map_err(|e| Error::Storage(format!("serialize batches: {e}")))?;
    let p = path(home, wallet);
    std::fs::write(&p, bytes).map_err(|e| Error::Storage(format!("write {}: {e}", p.display())))
}

/// Which batch an index came from, if any — so a collision can name the peer
/// whose batch was double-handed rather than only the slot number.
pub fn batch_of(batches: &[Batch], index: u64) -> Option<&Batch> {
    batches
        .iter()
        .find(|b| index >= b.first && index < b.first + b.count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_round_trip_and_attribution_works() {
        let dir = std::env::temp_dir().join(format!("uv-batches-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read(&dir, "w").is_empty(), "no ledger yet reads as empty");
        append(
            &dir,
            "w",
            Batch {
                peer: Some("carol".into()),
                first: 10,
                count: 5,
            },
        )
        .unwrap();
        let all = read(&dir, "w");
        assert_eq!(all.len(), 1);
        assert_eq!(
            batch_of(&all, 12).and_then(|b| b.peer.as_deref()),
            Some("carol")
        );
        assert!(batch_of(&all, 15).is_none(), "one past the end is outside");
        assert!(
            batch_of(&all, 9).is_none(),
            "one before the start is outside"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
