//! Mirror sync: how a phone reads Bitcoin without telling anyone what it holds.
//!
//! ## The problem this exists to avoid
//!
//! Safe receiving needs one chain lookup per hop of a coin's history
//! (`SPEC.md` §7.3): *did this nullifier's record win its race?* A phone
//! cannot run a full node, so the obvious design is to ask a server —
//! `GET /first_occurrence/<nf>` — and that single request hands the server
//! the two things the whole design exists to hide: **which coins are yours,
//! and when you are about to spend them.** A nullifier is a coin's true name.
//! Asking about it is telling.
//!
//! ## The shape that avoids it
//!
//! Mirrors serve **bulk pages of everything**, oldest first: every record and
//! every issuance from a height, with no query on them. The phone replays
//! those pages into the same [`RecordIndex`](crate::index::RecordIndex) the
//! desktop backend builds from a full node, and answers `first_occurrence`
//! **in-process, from its own index**. No nullifier is ever sent anywhere.
//! The mirror knows one thing: that somebody asked for blocks — which is what
//! every SPV wallet, every block explorer, and every node already reveals.
//!
//! That is the trade, stated plainly: bandwidth (everything, not the parts you
//! care about) bought in exchange for the query never existing. It is the same
//! trade Bitcoin's own compact filters make, and it grows with global usage —
//! measured and named in `spec/99-OPEN-PROBLEMS.md` under `[ACC]`, because it
//! is the argument the accumulator would eventually answer.
//!
//! ## What a mirror is trusted for, and what it is not
//!
//! **Not trusted for validity.** Every proof is verified on the phone, every
//! commitment opened locally, conservation checked in-circuit. A lying mirror
//! cannot make an invalid payment valid.
//!
//! **Trusted for completeness**, and only that: a mirror that *omits* a record
//! can make a double-spend look unopposed. That is why [`replay`] refuses a
//! feed with a hole in it by name, and why a view whose pages do not reach the
//! tip must answer `Unanswerable` rather than "nothing found" — the
//! distinction `wallet2::chain::Lookup` exists for ([`Synced::complete`]).
//! Cross-checking several mirrors turns the assumption into a detectable
//! disagreement rather than a silent one; [`disagreements`] reports it and
//! refuses to paper over it.

use serde::{Deserialize, Serialize};

use uv_kernel2::issuance::ISSUANCE_BYTES;
use uv_kernel2::record::RECORD_BYTES;

/// One page of chain data: everything from `from` through `through`, in
/// confirmation order.
///
/// Pages are **content-addressed by their own bytes** (`Page::digest`), so two
/// mirrors serving the same range either produce identical pages or produce a
/// difference a caller can name. Nothing here is filtered per caller — that
/// is the whole point, and a mirror that started filtering would be a mirror
/// that learned something.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page {
    /// First height this page speaks for.
    pub from: u64,
    /// Last height this page speaks for. A page may be empty of records and
    /// still be meaningful: it says *those blocks held nothing*, which is
    /// exactly the statement a gap cannot make.
    pub through: u64,
    /// The tip the mirror had when it built the page, so a caller can tell how
    /// far behind the page leaves it.
    pub tip: u64,
    /// The lowest height the mirror can answer for. **Not decoration**: a
    /// client that ignored this would treat "no record in the range I was
    /// given" as "no record exists", and a record below the floor is exactly
    /// what that misses. A view adopts this as its own `scan_floor`, which is
    /// what `accept` checks against an asset's `issued_below`.
    #[serde(default)]
    pub floor: u64,
    /// Spend records: `(hex bytes, height, tx index, vout)`.
    pub records: Vec<(String, u64, u32, u32)>,
    /// Issuance records: `(hex bytes, height)`.
    pub issuances: Vec<(String, u64)>,
}

impl Page {
    /// A content address for this page: the hash of its canonical encoding.
    ///
    /// Two mirrors that saw the same chain produce the same digest. Callers
    /// compare digests rather than diffing lists, so "these mirrors disagree"
    /// is one comparison and cannot be fudged by ordering.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.from.to_le_bytes());
        h.update(self.through.to_le_bytes());
        for (hexs, height, index, vout) in &self.records {
            h.update(hexs.as_bytes());
            h.update(height.to_le_bytes());
            h.update(index.to_le_bytes());
            h.update(vout.to_le_bytes());
        }
        for (hexs, height) in &self.issuances {
            h.update(hexs.as_bytes());
            h.update(height.to_le_bytes());
        }
        hex::encode(h.finalize())
    }

    /// Reject a page whose contents are not what a chain page can be.
    ///
    /// Cheap structural checks only — lengths, ranges, hex — because this
    /// runs on bytes a stranger sent. It is not a validity check and does not
    /// pretend to be: what makes a record *real* is the proof and the lineage,
    /// checked later and elsewhere. What this stops is a malformed page
    /// wedging the index it is replayed into.
    pub fn well_formed(&self) -> Result<(), String> {
        if self.from > self.through {
            return Err(format!(
                "page range is backwards: {}..{}",
                self.from, self.through
            ));
        }
        if self.through > self.tip {
            return Err(format!(
                "page claims height {} above its own tip {}",
                self.through, self.tip
            ));
        }
        for (hexs, height, _, _) in &self.records {
            if hex::decode(hexs).map(|b| b.len()) != Ok(RECORD_BYTES) {
                return Err(format!("record is not {RECORD_BYTES} bytes: {hexs}"));
            }
            if *height < self.from || *height > self.through {
                return Err(format!("record at height {height} is outside the page"));
            }
        }
        for (hexs, height) in &self.issuances {
            if hex::decode(hexs).map(|b| b.len()) != Ok(ISSUANCE_BYTES) {
                return Err(format!("issuance is not {ISSUANCE_BYTES} bytes: {hexs}"));
            }
            if *height < self.from || *height > self.through {
                return Err(format!("issuance at height {height} is outside the page"));
            }
        }
        Ok(())
    }
}

/// What a caller learned from one mirror in one sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synced {
    /// Highest height now covered, contiguously, from the floor.
    pub covered_through: u64,
    /// The mirror's own tip when it answered.
    pub tip: u64,
    /// Page digests in order — the material for cross-checking a second
    /// mirror without re-downloading anything.
    pub digests: Vec<String>,
}

impl Synced {
    /// Whether this view can answer for the whole chain up to the tip.
    ///
    /// A phone that is behind is not a phone that may guess: `accept` refuses
    /// on `Unanswerable`, which is what turns "I am still syncing" into a
    /// retry rather than into a double-spend accepted for free.
    ///
    /// **`tip == 0` is never complete**, and that clause is not a formality.
    /// A mirror serving an index that has scanned nothing reports tip 0; with
    /// a bare `covered_through >= tip` the client concluded `0 >= 0`, called
    /// itself caught up, and answered "no record exists" for a nullifier that
    /// was on chain. That is the fail-open this whole type exists to prevent,
    /// and it was found by pointing a real client at a real empty mirror.
    pub fn complete(&self) -> bool {
        self.tip > 0 && self.covered_through >= self.tip
    }
}

/// Compare what two mirrors said about the same range.
///
/// Returns the page indices whose digests differ. **An empty result is not
/// proof of honesty** — two mirrors can omit the same record, and colluding
/// mirrors are one mirror. It is proof that they agree, which is the strongest
/// thing cross-checking can establish and is worth stating precisely because
/// the temptation is to read it as more.
pub fn disagreements(a: &Synced, b: &Synced) -> Vec<usize> {
    a.digests
        .iter()
        .zip(b.digests.iter())
        .enumerate()
        .filter(|(_, (x, y))| x != y)
        .map(|(i, _)| i)
        .collect()
}

/// Replay a mirror's pages into a local index.
///
/// The index is the same one `BitcoinChain` builds from a full node, so what
/// the phone answers `first_occurrence` from is byte-for-byte the structure a
/// node-backed wallet answers from. That is deliberate: two index shapes would
/// be two first-occurrence rules.
///
/// **Contiguity is enforced, not assumed.** Pages must arrive covering the
/// range with no hole — a missing page is a range where "nothing found" would
/// be a lie, and this returns an error naming the first gap rather than
/// silently indexing around it. Everything downstream (`scan_floor`,
/// `Lookup::Unanswerable`) rests on the index's covered range meaning what it
/// says.
pub fn replay(
    index: &mut crate::index::RecordIndex,
    from: u64,
    pages: &[Page],
) -> Result<Synced, String> {
    let mut next = from;
    let mut tip = 0u64;
    let mut digests = Vec::with_capacity(pages.len());

    for p in pages {
        p.well_formed()?;
        if p.from != next {
            return Err(format!(
                "gap in the feed: expected a page starting at {next}, got one at {}",
                p.from
            ));
        }
        digests.push(p.digest());
        for (hexs, height, idx, vout) in &p.records {
            let bytes = hex::decode(hexs).map_err(|e| format!("record hex: {e}"))?;
            let arr: [u8; RECORD_BYTES] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "record length".to_string())?;
            index.insert(&arr, *height, *idx, *vout);
        }
        for (hexs, height) in &p.issuances {
            index.insert_issuance(hexs.clone(), *height);
        }
        tip = p.tip;
        next = p.through + 1;
    }

    let covered_through = next.saturating_sub(1);
    // The hash a page range is remembered by. A mirror feed carries no block
    // hashes — it is a record feed, not a header chain — so the marker is the
    // page digest, which is what a later cross-check compares anyway.
    if let Some(last) = digests.last() {
        index.advance_to(covered_through, format!("mirror:{last}"));
    }
    index.save();

    Ok(Synced {
        covered_through,
        tip,
        digests,
    })
}

/// Build one page from a local index — what a mirror serves.
///
/// The mirror is simply a wallet that keeps a full index and hands out ranges
/// of it. There is no privileged data structure here and no query surface: a
/// caller names a height range, and gets everything in it.
pub fn build_page(index: &crate::index::RecordIndex, from: u64, through: u64, tip: u64) -> Page {
    Page {
        from,
        through: through.min(tip),
        tip,
        floor: index.scan_floor(),
        records: index.records_in(from, through.min(tip)),
        issuances: index.issuances_in(from, through.min(tip)),
    }
}

/// A chain view a phone can hold: an index fed by mirror pages, questioned
/// in-process.
///
/// It implements the same [`Chain`](uv_wallet2::chain::Chain) trait the
/// node-backed backend does, so `accept`, `reconcile` and everything else run
/// unchanged — the phone's safety rules are the desktop's, not a lighter
/// variant of them. What differs is only where the bytes came from.
///
/// **`sync` is not optional and not automatic.** This view answers from what
/// it has replayed; a caller that never syncs holds a view of nothing, which
/// reports `Unanswerable` rather than "no conflicting record exists". That is
/// the whole safety posture in one sentence: an incomplete view refuses
/// instead of guessing.
pub struct MirrorView {
    index: std::sync::Mutex<crate::index::RecordIndex>,
    /// The tip the last sync learned, and whether that sync reached it.
    seen: std::sync::Mutex<(u64, bool)>,
    /// The floor the mirror declared. Adopted rather than assumed zero: this
    /// view can only answer for what the mirror could, and `accept` compares
    /// it against the asset's `issued_below`.
    floor: std::sync::Mutex<u64>,
}

impl MirrorView {
    /// Open (or start) the local index this view answers from.
    ///
    /// Floor zero always: a mirror-fed phone that could not answer for the
    /// whole chain would have to refuse everything anyway, so a partial floor
    /// is not a configuration worth having.
    pub fn open(index_path: impl AsRef<std::path::Path>) -> Self {
        MirrorView {
            index: std::sync::Mutex::new(crate::index::RecordIndex::load(index_path, 0)),
            seen: std::sync::Mutex::new((0, false)),
            floor: std::sync::Mutex::new(0),
        }
    }

    /// Replay pages from a mirror into the local index.
    ///
    /// `from` must be where this view left off — [`replay`] refuses a gap by
    /// name rather than indexing around it.
    pub fn sync(&self, from: u64, pages: &[Page]) -> Result<Synced, String> {
        let mut idx = self.index.lock().expect("index lock");
        let declared = pages.iter().map(|p| p.floor).max().unwrap_or(0);
        let synced = replay(&mut idx, from, pages)?;
        *self.seen.lock().expect("seen lock") = (synced.tip, synced.complete());
        *self.floor.lock().expect("floor lock") = declared;
        Ok(synced)
    }

    /// The next height to ask a mirror for.
    pub fn next_height(&self) -> u64 {
        self.index.lock().expect("index lock").next_height()
    }

    /// Whether the last sync reached the mirror's tip. A false here is why
    /// lookups answer `Unanswerable`.
    pub fn caught_up(&self) -> bool {
        self.seen.lock().expect("seen lock").1
    }
}

impl uv_wallet2::chain::Chain for MirrorView {
    fn first_occurrence(&self, nf: &uv_air::poseidon2::Digest) -> uv_wallet2::chain::Lookup {
        use uv_wallet2::chain::{Lookup, Occurrence};

        // **The privacy claim, in code**: the nullifier is used here, against
        // a local map, and goes nowhere. There is no request to make.
        let (tip, caught_up) = *self.seen.lock().expect("seen lock");
        if !caught_up {
            // Behind the tip: a record could exist in the range not yet
            // replayed, so "not found" would be a guess.
            return Lookup::Unanswerable;
        }
        let key = uv_kernel2::digest::encode(nf);
        let idx = self.index.lock().expect("index lock");
        match idx.get(&key) {
            Some((bytes, at)) => {
                if at.height > tip {
                    return Lookup::Unanswerable;
                }
                let mut bundle = [0u8; uv_kernel2::digest::DIGEST_BYTES];
                bundle.copy_from_slice(&bytes[uv_kernel2::digest::DIGEST_BYTES..]);
                match uv_kernel2::digest::decode(&bundle) {
                    Some(bundle_hash) => Lookup::Found(Occurrence {
                        bundle_hash,
                        depth: tip - at.height + 1,
                    }),
                    // A record whose bundle half is not a canonical digest is
                    // not a record. Refusing beats reporting a hash nobody
                    // can have produced.
                    None => Lookup::Unanswerable,
                }
            }
            None => Lookup::None,
        }
    }

    fn publish(
        &mut self,
        _record: &uv_kernel2::record::Record,
    ) -> Result<(), uv_wallet2::chain::PublishError> {
        // A mirror is a **reading** device. Publishing needs a funded Bitcoin
        // wallet and a transaction, which a mirror neither has nor should be
        // handed; a phone publishes through its own node or a broadcast
        // service, and that path is separate on purpose — asking a mirror to
        // publish would hand it the record to censor.
        Err(uv_wallet2::chain::PublishError(
            "a mirror view reads the chain; it cannot publish".into(),
        ))
    }

    fn publish_issuance(
        &mut self,
        _issuance: &uv_kernel2::issuance::Issuance,
    ) -> Result<(), uv_wallet2::chain::PublishError> {
        Err(uv_wallet2::chain::PublishError(
            "a mirror view reads the chain; it cannot publish".into(),
        ))
    }

    fn issuances(&self) -> Vec<uv_kernel2::issuance::Issuance> {
        self.index.lock().expect("index lock").issuances()
    }

    fn tip(&self) -> Result<u64, uv_wallet2::chain::ChainViewError> {
        Ok(self.seen.lock().expect("seen lock").0)
    }

    fn rollback_epoch(&self) -> u64 {
        self.index.lock().expect("index lock").rollback_epoch()
    }

    fn refresh(&self) {
        // Nothing to do in-process: a mirror view is refreshed by `sync`,
        // which needs pages the caller must fetch. Said explicitly rather than
        // left to a default body, because the default would be the fail-open
        // answer — and `caught_up` is what actually gates the lookups.
    }

    fn scan_floor(&self) -> u64 {
        // The MIRROR's floor, not the local file's. The local index is opened
        // at zero because it is ours to fill; what bounds the answers is how
        // far back the feed could see.
        *self.floor.lock().expect("floor lock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(from: u64, through: u64, tip: u64) -> Page {
        Page {
            from,
            through,
            tip,
            floor: 0,
            records: Vec::new(),
            issuances: Vec::new(),
        }
    }

    fn a_record(height: u64) -> (String, u64, u32, u32) {
        (hex::encode([7u8; RECORD_BYTES]), height, 0, 0)
    }

    #[test]
    fn a_well_formed_page_passes_and_a_malformed_one_names_its_problem() {
        let mut p = page(10, 20, 100);
        p.records.push(a_record(15));
        assert!(p.well_formed().is_ok());

        let mut backwards = page(20, 10, 100);
        backwards.records.push(a_record(15));
        assert!(backwards.well_formed().is_err());

        // A record outside the range it claims to cover: the page would insert
        // history it never promised, at a height nothing else vouches for.
        let mut outside = page(10, 20, 100);
        outside.records.push(a_record(25));
        assert!(outside.well_formed().is_err());

        // Above its own tip — a mirror claiming blocks it does not have.
        let above = page(10, 200, 100);
        assert!(above.well_formed().is_err());

        // Wrong length: not a record, whatever else it is.
        let mut short = page(10, 20, 100);
        short.records.push((hex::encode([1u8; 8]), 15, 0, 0));
        assert!(short.well_formed().is_err());
    }

    /// The property cross-checking rests on: same chain, same bytes, same
    /// digest — and one different record is one different digest.
    #[test]
    fn identical_pages_share_a_digest_and_different_ones_do_not() {
        let mut a = page(0, 50, 60);
        a.records.push(a_record(3));
        let mut b = page(0, 50, 60);
        b.records.push(a_record(3));
        assert_eq!(a.digest(), b.digest());

        // A mirror that omits one record produces a different digest — which
        // is the omission this check exists to surface.
        let empty = page(0, 50, 60);
        assert_ne!(a.digest(), empty.digest());

        // ...and so does one that moves a record to another height.
        let mut moved = page(0, 50, 60);
        moved.records.push(a_record(4));
        assert_ne!(a.digest(), moved.digest());
    }

    #[test]
    fn a_view_that_has_not_reached_the_tip_is_not_complete() {
        let behind = Synced {
            covered_through: 90,
            tip: 100,
            digests: vec![],
        };
        assert!(
            !behind.complete(),
            "still syncing must never read as complete"
        );
        let caught_up = Synced {
            covered_through: 100,
            tip: 100,
            digests: vec![],
        };
        assert!(caught_up.complete());
    }

    fn temp_index(tag: &str) -> (crate::index::RecordIndex, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!("uv-mirror-{tag}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        (crate::index::RecordIndex::load(&p, 0), p)
    }

    /// The happy path, and the property that matters: after replaying, the
    /// phone answers a nullifier lookup **from its own index** — the mirror was
    /// never told which one.
    #[test]
    fn replayed_pages_answer_lookups_locally() {
        let (mut idx, path) = temp_index("replay");
        let mut record = [0u8; RECORD_BYTES];
        record[..8].copy_from_slice(&[9u8; 8]);
        let mut p = page(0, 10, 10);
        p.records.push((hex::encode(record), 5, 1, 0));
        let synced = replay(&mut idx, 0, &[p]).expect("well-formed feed");

        assert!(synced.complete(), "covered through the mirror's tip");
        let nf: [u8; 32] = record[..32].try_into().unwrap();
        let found = idx.get(&nf).expect("the record is in the local index");
        assert_eq!(found.1.height, 5);
        let _ = std::fs::remove_file(path);
    }

    /// A hole in the feed is refused by name. Indexing around it would make
    /// "nothing found" a lie for every height in the gap — which is exactly
    /// how a mirror that omits a record makes a double-spend look unopposed.
    /// The end-to-end property: what a mirror builds from its index is what a
    /// phone's index becomes. Two indexes, one chain, and the phone's answer
    /// to a nullifier lookup matches the mirror's — without the nullifier ever
    /// having been sent.
    #[test]
    fn a_page_built_from_one_index_reproduces_it_in_another() {
        let (mut server, sp) = temp_index("server");
        let mut record = [0u8; RECORD_BYTES];
        record[..8].copy_from_slice(&[42u8; 8]);
        server.insert(&record, 7, 2, 0);
        // A REAL issuance, encoded: junk bytes are dropped by the strict
        // decoder (a good thing, and how the first version of this test
        // discovered it), so a fixture that is not a record proves nothing.
        let iss = uv_kernel2::issuance::Issuance {
            amount: 1_000,
            asset: [p3_baby_bear::BabyBear::new(0xA5); 8],
            commitment: [p3_baby_bear::BabyBear::new(0xB6); 8],
        };
        server.insert_issuance(hex::encode(iss.encode()), 4);

        let p = build_page(&server, 0, 20, 20);
        assert_eq!(p.records.len(), 1, "the page carries the record");
        assert_eq!(p.issuances.len(), 1, "and the issuance");

        let (mut phone, pp) = temp_index("phone");
        let synced = replay(&mut phone, 0, &[p]).expect("well formed");
        assert!(synced.complete());

        let nf: [u8; 32] = record[..32].try_into().unwrap();
        assert_eq!(
            phone.get(&nf).map(|f| f.1.height),
            server.get(&nf).map(|f| f.1.height),
            "the phone answers what the mirror would have, from its own index"
        );
        assert_eq!(phone.issuances().len(), 1, "issuances travel too");
        let _ = std::fs::remove_file(sp);
        let _ = std::fs::remove_file(pp);
    }

    #[test]
    fn a_gap_in_the_feed_is_refused_rather_than_indexed_around() {
        let (mut idx, path) = temp_index("gap");
        let first = page(0, 10, 30);
        let skipped = page(21, 30, 30); // 11..20 missing
        let err = replay(&mut idx, 0, &[first, skipped]).expect_err("must refuse");
        assert!(err.contains("gap"), "the refusal names the problem: {err}");
        let _ = std::fs::remove_file(path);
    }

    /// A page that does not start where the caller asked is the same hazard
    /// arriving first rather than in the middle.
    #[test]
    fn a_feed_that_starts_late_is_refused() {
        let (mut idx, path) = temp_index("late");
        let err = replay(&mut idx, 0, &[page(5, 10, 10)]).expect_err("must refuse");
        assert!(err.contains("gap"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    /// **The safety property of a light client, in one test.** A view that has
    /// not caught up must answer `Unanswerable` — never `None` — because
    /// "I have not looked there yet" and "nothing is there" are the same
    /// sentence to a caller that cannot tell them apart, and the second one
    /// accepts a double-spend for free.
    #[test]
    fn a_view_behind_the_tip_refuses_rather_than_reporting_nothing_found() {
        use uv_wallet2::chain::{Chain, Lookup};

        let p = std::env::temp_dir().join(format!("uv-mirrorview-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let view = MirrorView::open(&p);

        let nf = [p3_baby_bear::BabyBear::new(0x5151); 8];
        // Never synced: the view knows nothing and says so.
        assert!(matches!(view.first_occurrence(&nf), Lookup::Unanswerable));

        // Synced, but the mirror's tip is beyond what the pages covered.
        let behind = Page {
            from: 0,
            through: 10,
            tip: 99,
            floor: 0,
            records: vec![],
            issuances: vec![],
        };
        view.sync(0, &[behind]).expect("well formed");
        assert!(!view.caught_up(), "10 of 99 is not caught up");
        assert!(
            matches!(view.first_occurrence(&nf), Lookup::Unanswerable),
            "a view behind the tip must refuse"
        );

        // Caught up, and now a miss is a real answer: nothing is there.
        let rest = Page {
            from: 11,
            through: 99,
            tip: 99,
            floor: 0,
            records: vec![],
            issuances: vec![],
        };
        view.sync(11, &[rest]).expect("well formed");
        assert!(view.caught_up());
        assert!(
            matches!(view.first_occurrence(&nf), Lookup::None),
            "a complete view may answer that nothing is there"
        );
        let _ = std::fs::remove_file(p);
    }

    /// **The fail-open this found in the field, kept as a regression.** A mirror
    /// whose index has scanned nothing reports tip 0. With `complete()` as a
    /// bare `covered_through >= tip`, a client synced 0→0, concluded `0 >= 0`,
    /// called itself caught up, and answered `None` — "no record exists" — for
    /// a nullifier that was on public signet. `None` is what lets a
    /// double-spend through.
    #[test]
    fn an_empty_mirror_never_makes_a_view_look_complete() {
        use uv_wallet2::chain::{Chain, Lookup};

        let p = std::env::temp_dir().join(format!("uv-emptymirror-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let view = MirrorView::open(&p);

        // Exactly what an empty mirror serves.
        let nothing = Page {
            from: 0,
            through: 0,
            tip: 0,
            floor: 0,
            records: vec![],
            issuances: vec![],
        };
        let synced = view.sync(0, &[nothing]).expect("well formed");
        assert!(
            !synced.complete(),
            "a mirror that has scanned nothing must never read as caught up"
        );
        assert!(!view.caught_up());
        let nf = [p3_baby_bear::BabyBear::new(0x7777); 8];
        assert!(
            matches!(view.first_occurrence(&nf), Lookup::Unanswerable),
            "and every lookup must refuse rather than report nothing-found"
        );
        let _ = std::fs::remove_file(p);
    }

    /// A view answers only for what the mirror could see. The floor travels in
    /// the pages and is adopted, so `accept` can compare it against an asset's
    /// `issued_below` instead of trusting a zero that was never true.
    #[test]
    fn a_view_adopts_the_mirrors_floor() {
        use uv_wallet2::chain::Chain;

        let p = std::env::temp_dir().join(format!("uv-mirrorfloor-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let view = MirrorView::open(&p);
        assert_eq!(view.scan_floor(), 0, "nothing synced yet");

        let page = Page {
            from: 500,
            through: 900,
            tip: 900,
            floor: 500,
            records: vec![],
            issuances: vec![],
        };
        view.sync(500, &[page]).expect("well formed");
        assert_eq!(
            view.scan_floor(),
            500,
            "the mirror said it cannot see below 500, so neither can this view"
        );
        let _ = std::fs::remove_file(p);
    }

    /// A mirror is a reading device. Asking it to publish is refused with a
    /// sentence, not silently swallowed — handing a mirror the record to
    /// broadcast is handing it the record to censor.
    #[test]
    fn a_mirror_view_refuses_to_publish() {
        use uv_wallet2::chain::Chain;
        let p = std::env::temp_dir().join(format!("uv-mirrorpub-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let mut view = MirrorView::open(&p);
        let rec = uv_kernel2::record::Record {
            nullifier: [p3_baby_bear::BabyBear::new(1); 8],
            bundle_hash: [p3_baby_bear::BabyBear::new(2); 8],
        };
        let err = view.publish(&rec).expect_err("must refuse");
        assert!(err.to_string().contains("cannot publish"), "{err}");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn disagreeing_mirrors_are_named_by_page() {
        let a = Synced {
            covered_through: 100,
            tip: 100,
            digests: vec!["aa".into(), "bb".into(), "cc".into()],
        };
        let b = Synced {
            covered_through: 100,
            tip: 100,
            digests: vec!["aa".into(), "XX".into(), "cc".into()],
        };
        assert_eq!(disagreements(&a, &b), vec![1]);
        assert!(disagreements(&a, &a).is_empty(), "agreement is empty");
    }
}
