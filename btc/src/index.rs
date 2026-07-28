//! A persistent record index: nullifier → the record that claimed it first.
//!
//! Without this, `first_occurrence` re-downloads and re-parses every block from
//! `scan_from` to the tip on **every single lookup**. That was survivable while
//! a receiver checked one nullifier per payment; it stopped being survivable
//! when the ancestry rule made a receiver check *every* hop in a note's
//! history: n ancestors meant n full rescans.
//!
//! So: scan forward once, remember what was found, advance with the tip.
//! Lookups become a map read.
//!
//! **First occurrence is enforced on insert** — a nullifier already present is
//! never overwritten — which is the same rule `Chain::publish` promises,
//! applied to the index that answers for it.
//!
//! Deliberately type-agnostic: keys are the raw nullifier bytes, entries the
//! raw record — the index neither parses nor validates, it remembers. The
//! widths come from `kernel2` rather than being written as `32` and `64` here,
//! because a hand-mirrored constant is a constant that eventually stops
//! mirroring, and this one splits records.
//! (Canonicality is the consensus layer's job: `uv_kernel2::record::decode`
//! rejects non-canonical bytes when the wallet reads the answer.)
//!
//! Deliberately simple: a JSON file rewritten on change, which suits a POC
//! scanning a regtest or signet range. A real wallet wants an embedded k/v
//! store and a reorg rollback path (spec/99), and this is not that.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use uv_kernel2::digest::DIGEST_BYTES;
use uv_kernel2::record::RECORD_BYTES;

/// A found record's position.
#[derive(Clone, Copy, Debug)]
pub struct FoundAt {
    pub height: u64,
    pub index: u32,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    /// The full record, hex.
    record_hex: String,
    height: u64,
    index: u32,
}

/// Bump when the on-disk shape changes. A mismatch **rebuilds** rather than
/// loading what it can — see [`RecordIndex::load`].
const FORMAT_VERSION: u32 = 2;

/// How far back a reorg can be detected and undone. Bitcoin's deepest recorded
/// mainnet reorg was 24 blocks, in 2013, caused by a consensus bug. A day of
/// blocks is generous; anything deeper rebuilds from the floor, which is slow
/// and correct.
///
/// **Public because the issuance floor has to agree with it.** `uv issue`
/// stamps an asset's floor this far below the tip; if that margin were the
/// shallower of the two, a reorg the index can undo could still surface a
/// record *beneath* a floor already written down, and the floor would hide it.
/// The two used to be independent `144`s in different crates with no link
/// between them. Now the CLI derives its margin from this.
pub const REORG_WINDOW: usize = 144;

#[derive(Serialize, Deserialize, Default)]
struct State {
    /// On-disk format. Absent in old files, which is exactly what makes them
    /// fail to parse and get rebuilt.
    version: u32,
    /// The scan floor this index was built for. If the caller later asks for an
    /// *earlier* floor, the index cannot answer and is rebuilt.
    scan_from: u64,
    /// The highest scanned block, **with its hash**.
    ///
    /// These two travel together deliberately. A height without a hash is a
    /// claim to have scanned a range that cannot be checked against the chain,
    /// which is the shape of a silent blind spot: everything downstream would
    /// trust `scanned_through` and nothing could tell it had gone stale. Keeping
    /// them in one field means they cannot drift apart.
    scanned_through: Option<(u64, String)>,
    /// Recent block hashes, newest last, capped at [`REORG_WINDOW`]. Used only
    /// to *locate* a fork once one has been detected.
    recent: Vec<(u64, String)>,
    /// How many rollbacks this index has performed. Monotonic, persisted, and
    /// read by wallets to decide whether they owe a reconciliation — an
    /// in-memory flag would be lost, since every `uv` invocation is its own
    /// process.
    rollbacks: u64,
    /// nullifier hex → first occurrence.
    first: HashMap<String, Entry>,
}

pub struct RecordIndex {
    path: PathBuf,
    state: State,
}

impl RecordIndex {
    /// The height this index started from. Zero means it was *configured* to
    /// cover the whole chain; anything else means there is history it cannot
    /// answer for.
    ///
    /// Read carefully by `BitcoinChain::index_covers_everything`, which treats
    /// zero as "this view is complete". That is a claim about configuration,
    /// not about work done — what makes it true in practice is that a scan
    /// which cannot reach the tip propagates its error and the lookup answers
    /// `Unanswerable` rather than `None`. Stated because the inference
    /// "floor == 0 therefore every block below the tip was parsed" is the kind
    /// of step `spec/99 [ASSUMPTIONS]` is about.
    pub fn scan_floor(&self) -> u64 {
        self.state.scan_from
    }

    /// Load the index, or start fresh.
    ///
    /// A stored index built from a *later* floor than the one now requested is
    /// discarded rather than reused: it cannot see the earlier blocks, so
    /// trusting it would silently narrow the view — failing open, which is the
    /// exact shape of audit finding B2.
    pub fn load(path: impl AsRef<Path>, scan_from: u64) -> Self {
        let path = path.as_ref().to_path_buf();
        let state = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<State>(&b).ok())
            // A different on-disk shape is rebuilt, never partially trusted.
            // The tempting alternative — `#[serde(default)]` on the new fields
            // — would load an old index claiming to have scanned a range it
            // holds no hashes for, so reorg detection could not run over it and
            // nothing would say so. Slow and correct beats fast and blind.
            .filter(|s| s.version == FORMAT_VERSION)
            .filter(|s| s.scan_from <= scan_from)
            .unwrap_or(State {
                version: FORMAT_VERSION,
                scan_from,
                ..Default::default()
            });
        RecordIndex { path, state }
    }

    /// The next height needing a scan.
    pub fn next_height(&self) -> u64 {
        match &self.state.scanned_through {
            Some((h, _)) => h + 1,
            None => self.state.scan_from,
        }
    }

    /// The highest scanned block and its hash, if anything has been scanned.
    pub fn tip_scanned(&self) -> Option<(u64, String)> {
        self.state.scanned_through.clone()
    }

    /// Hashes we could compare against, newest first.
    pub fn recent(&self) -> impl Iterator<Item = (u64, String)> + '_ {
        self.state.recent.iter().rev().cloned()
    }

    /// How many rollbacks this index has done. Wallets compare this against
    /// what they last reconciled at.
    pub fn rollback_epoch(&self) -> u64 {
        self.state.rollbacks
    }

    /// Undo everything at or above `fork_height`.
    ///
    /// Dropping and rescanning is sufficient, and the reason is worth stating:
    /// the chain below a fork is bit-identical to what was scanned — that is
    /// what a matching block hash proves — so no entry below the fork can be
    /// affected. Entries at or above it are exactly the ones that might have
    /// been in orphaned blocks.
    ///
    /// First occurrence re-establishes itself on rescan without extra work,
    /// because `insert` keeps the earliest entry and rescanning runs ascending
    /// from the fork: a record that survived at height 100 still outranks a
    /// competitor found later at 105.
    ///
    /// Note `>=`, not `>`. The fork block's *own* records must go; leaving one
    /// behind is a phantom first occurrence that outranks the real one forever.
    pub fn rollback_to(&mut self, fork_height: u64) {
        self.discard_from(fork_height);
        self.state.rollbacks += 1;
    }

    /// Abort an uncommitted scan range without reporting a chain rollback.
    ///
    /// `BitcoinChain` scans several RPC responses into memory, then validates
    /// that the tip stayed fixed for the whole batch. If the node moved during
    /// those calls, every staged entry at `from` and above must disappear before
    /// the lookup returns `Unanswerable`. This is transaction rollback, not a
    /// confirmed Bitcoin reorg, so it does not advance the wallet-facing epoch.
    pub(crate) fn discard_from(&mut self, from: u64) {
        self.state.first.retain(|_, e| e.height < from);
        self.state.recent.retain(|(h, _)| *h < from);
        self.state.scanned_through = self.state.recent.last().cloned().filter(|(h, _)| *h < from);
    }

    /// Throw everything away and rescan from the floor. Used when a reorg is
    /// deeper than [`REORG_WINDOW`], where the fork cannot be located — rolling
    /// back to the oldest hash held would look right and be wrong, because the
    /// fork may be below it.
    pub fn rebuild(&mut self) {
        let (floor, rollbacks) = (self.state.scan_from, self.state.rollbacks);
        self.state = State {
            version: FORMAT_VERSION,
            scan_from: floor,
            rollbacks: rollbacks + 1,
            ..Default::default()
        };
    }

    /// Record a first occurrence of a raw record. An existing entry
    /// wins — that is the rule this index exists to answer for.
    pub fn insert(&mut self, record: &[u8; RECORD_BYTES], height: u64, index: u32) {
        self.state
            .first
            .entry(hex::encode(&record[..DIGEST_BYTES]))
            .or_insert(Entry {
                record_hex: hex::encode(record),
                height,
                index,
            });
    }

    /// Mark everything through `height` as scanned, remembering its hash.
    pub fn advance_to(&mut self, height: u64, hash: String) {
        self.state.scanned_through = Some((height, hash.clone()));
        self.state.recent.push((height, hash));
        let len = self.state.recent.len();
        if len > REORG_WINDOW {
            self.state.recent.drain(..len - REORG_WINDOW);
        }
    }

    /// Look up a nullifier's first occurrence: the raw record and where it sat.
    pub fn get(&self, nf: &[u8; DIGEST_BYTES]) -> Option<([u8; RECORD_BYTES], FoundAt)> {
        let e = self.state.first.get(&hex::encode(nf))?;
        let bytes = hex::decode(&e.record_hex).ok()?;
        let arr: [u8; RECORD_BYTES] = bytes.as_slice().try_into().ok()?;
        Some((
            arr,
            FoundAt {
                height: e.height,
                index: e.index,
            },
        ))
    }

    pub fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec(&self.state) {
            let _ = std::fs::write(&self.path, bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(nf: u8, bh: u8) -> [u8; RECORD_BYTES] {
        let mut r = [0u8; RECORD_BYTES];
        r[..DIGEST_BYTES].fill(nf);
        r[DIGEST_BYTES..].fill(bh);
        r
    }

    #[test]
    fn first_occurrence_wins_on_insert() {
        let dir = tempfile::tempdir().unwrap();
        let mut ix = RecordIndex::load(dir.path().join("ix.json"), 0);
        ix.insert(&rec(1, 10), 100, 0);
        ix.insert(&rec(1, 99), 200, 3); // a later, conflicting claim
        let (got, at) = ix.get(&[1u8; DIGEST_BYTES]).unwrap();
        assert_eq!(got[32], 10, "the first claim stands");
        assert_eq!(at.height, 100);
    }

    #[test]
    fn it_persists_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ix.json");
        let mut ix = RecordIndex::load(&p, 50);
        assert_eq!(ix.next_height(), 50, "starts at the floor");
        ix.insert(&rec(2, 20), 60, 1);
        ix.advance_to(70, "h70".into());
        ix.save();

        let ix2 = RecordIndex::load(&p, 50);
        assert_eq!(
            ix2.next_height(),
            71,
            "resumes after the last scanned block"
        );
        assert!(ix2.get(&[2u8; 32]).is_some());
    }

    #[test]
    fn an_index_built_from_a_later_floor_is_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ix.json");
        let mut ix = RecordIndex::load(&p, 500);
        ix.insert(&rec(3, 30), 600, 0);
        ix.advance_to(700, "h700".into());
        ix.save();

        // Now ask for a wider view. The stored index never saw blocks 100..500,
        // so reusing it would silently narrow the chain view.
        let ix2 = RecordIndex::load(&p, 100);
        assert_eq!(ix2.next_height(), 100, "rebuilt from the wider floor");
        assert!(ix2.get(&[3u8; 32]).is_none(), "stale entries dropped");
    }
}

#[cfg(test)]
mod rollback {
    use super::*;

    fn rec(nf: u8, bundle: u8) -> [u8; RECORD_BYTES] {
        let mut r = [0u8; RECORD_BYTES];
        r[..DIGEST_BYTES].fill(nf);
        r[DIGEST_BYTES..].fill(bundle);
        r
    }

    fn fresh(dir: &tempfile::TempDir, floor: u64) -> RecordIndex {
        RecordIndex::load(dir.path().join("ix.json"), floor)
    }

    /// The chain below a fork is bit-identical to what was scanned — that is
    /// what a matching block hash proves — so entries below it must survive.
    #[test]
    fn entries_below_the_fork_survive() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        ix.insert(&rec(1, 1), 100, 0);
        ix.advance_to(100, "a".into());
        ix.insert(&rec(2, 2), 110, 0);
        ix.advance_to(110, "b".into());

        ix.rollback_to(105);
        assert!(
            ix.get(&[1u8; DIGEST_BYTES]).is_some(),
            "height 100 is below the fork"
        );
        assert!(ix.get(&[2u8; 32]).is_none(), "height 110 is above it");
    }

    /// `>=`, not `>`. A record in the fork block itself must go: leaving one
    /// behind is a phantom first occurrence that outranks the real one forever.
    #[test]
    fn a_record_in_the_fork_block_itself_does_not_survive() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        ix.insert(&rec(1, 1), 100, 0);
        ix.advance_to(100, "a".into());
        ix.rollback_to(100);
        assert!(
            ix.get(&[1u8; DIGEST_BYTES]).is_none(),
            "the fork block's own records are exactly the ones in doubt"
        );
    }

    /// First occurrence must re-establish itself on rescan without extra
    /// machinery: `insert` keeps the earliest, and rescanning runs ascending.
    #[test]
    fn a_surviving_earlier_record_still_outranks_a_later_competitor() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        ix.insert(&rec(1, 0xAA), 100, 0);
        ix.advance_to(100, "a".into());
        ix.advance_to(110, "b".into());
        ix.rollback_to(105);
        // Rescan finds a competitor for the same nullifier, higher up.
        ix.insert(&rec(1, 0xBB), 106, 0);
        let (found, _) = ix.get(&[1u8; DIGEST_BYTES]).expect("still there");
        assert_eq!(found[32], 0xAA, "the height-100 record must still win");
    }

    /// Rolling back past everything leaves the index empty and rescanning from
    /// the floor, not claiming to have scanned anything.
    #[test]
    fn rolling_back_past_everything_resets_to_the_floor() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 50);
        ix.insert(&rec(1, 1), 60, 0);
        ix.advance_to(60, "a".into());
        ix.rollback_to(50);
        assert_eq!(ix.next_height(), 50);
        assert!(ix.tip_scanned().is_none());
    }

    /// A moving RPC view must not leave a half-scanned fork in memory. This is
    /// the implementation counterpart of `formal/indexer.qnt`'s `midscanUnsafe`
    /// counterexample.
    #[test]
    fn aborting_a_scan_discards_every_staged_entry() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        ix.insert(&rec(1, 1), 0, 0);
        ix.advance_to(0, "stable".into());
        let epoch = ix.rollback_epoch();

        ix.insert(&rec(2, 2), 1, 0);
        ix.advance_to(1, "old-fork-1".into());
        ix.insert(&rec(3, 3), 2, 0);
        ix.advance_to(2, "new-fork-2".into());
        ix.discard_from(1);

        assert!(ix.get(&[1u8; 32]).is_some(), "committed prefix survives");
        assert!(ix.get(&[2u8; 32]).is_none(), "old-fork staging removed");
        assert!(ix.get(&[3u8; 32]).is_none(), "new-fork staging removed");
        assert_eq!(ix.next_height(), 1);
        assert_eq!(
            ix.rollback_epoch(),
            epoch,
            "aborting an uncommitted batch is not a detected chain rollback"
        );
    }

    /// A reorg deeper than the window rebuilds. The floor is kept; everything
    /// else goes.
    #[test]
    fn a_rebuild_keeps_the_floor_and_drops_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 50);
        ix.insert(&rec(1, 1), 60, 0);
        ix.advance_to(60, "a".into());
        ix.rebuild();
        assert_eq!(ix.next_height(), 50, "floor survives");
        assert!(ix.get(&[1u8; DIGEST_BYTES]).is_none());
        assert!(ix.tip_scanned().is_none());
    }

    /// The window is bounded, or the file grows without limit.
    #[test]
    fn the_hash_window_is_capped() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        for h in 0..(REORG_WINDOW as u64 + 50) {
            ix.advance_to(h, format!("h{h}"));
        }
        assert_eq!(ix.recent().count(), REORG_WINDOW);
        assert_eq!(ix.tip_scanned().unwrap().0, REORG_WINDOW as u64 + 49);
    }

    /// Wallets read this across process boundaries to decide whether they owe a
    /// reconciliation, so it must survive a save/load and only ever increase.
    #[test]
    fn the_rollback_epoch_is_monotonic_and_persisted() {
        let d = tempfile::tempdir().unwrap();
        let mut ix = fresh(&d, 0);
        assert_eq!(ix.rollback_epoch(), 0);
        ix.advance_to(10, "a".into());
        ix.rollback_to(5);
        ix.rollback_to(3);
        ix.save();
        assert_eq!(
            RecordIndex::load(d.path().join("ix.json"), 0).rollback_epoch(),
            2
        );
    }

    /// The trap the assessment named first: an old-format file must be rebuilt,
    /// never partially trusted. `#[serde(default)]` here would load an index
    /// claiming to have scanned a range it holds no hashes for — so detection
    /// could not run over it, and nothing would say so.
    #[test]
    fn an_old_format_index_is_rebuilt_rather_than_loaded_blind() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ix.json");
        // Exactly the previous shape: no version, no hashes, but a confident
        // `scanned_through`.
        std::fs::write(
            &p,
            br#"{"scan_from":0,"scanned_through":900000,"first":{}}"#,
        )
        .unwrap();
        let ix = RecordIndex::load(&p, 0);
        assert_eq!(
            ix.next_height(),
            0,
            "an unversioned index must rescan, not inherit a blind 900000"
        );
        assert!(ix.tip_scanned().is_none());
    }
}
