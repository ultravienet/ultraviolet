//! The wallet's view of Bitcoin: first occurrences of nullifiers, nothing else.
//!
//! The trait is deliberately tiny — the base rail needs only "what was the
//! first record for this nullifier, and how deep is it". `MockChain` exists
//! for tests and models the two behaviours that matter: publish is
//! first-occurrence (a second record for a known nullifier is a free no-op,
//! matching the signet demo's measured behaviour), and reorgs can drop
//! records (which is what [`crate::reconcile`] exists to survive).

use serde::{Deserialize, Serialize};
use uv_air::wots::Digest;
use uv_kernel2::issuance::Issuance;
use uv_kernel2::record::Record;

/// A first occurrence, as deep as the chain currently sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Occurrence {
    pub bundle_hash: Digest,
    /// Confirmations: 0 = mempool-visible only (a payment can be *seen* in
    /// seconds; it is trusted at the policy's depth). The backend computes
    /// this because only it knows what "confirmed" means for its chain.
    pub depth: u64,
}

/// Why a record could not be published. Carries a message rather than a
/// taxonomy: every current cause is "the node said no", and the caller's
/// response is the same either way — keep the durable spend and retry.
#[derive(Debug)]
pub struct PublishError(pub String);

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What a chain view can say about a nullifier.
///
/// **Three answers, not two, and the third is the whole point.** This used to
/// be `Option<Occurrence>`, which conflated *"no record exists"* — a safe,
/// fail-closed answer that correctly refuses a payment — with *"my view cannot
/// see far enough back to know"*, which is fail-**open**: it looks exactly like
/// "no conflicting record", so an index that starts above an earlier
/// double-spend makes the double-spend look valid.
///
/// There is deliberately no `as_option()`, no `Default`, and no `From<Option>`.
/// The value of this type is that adding the third variant turned every call
/// site into a compile error until somebody decided what it meant there. One
/// convenience conversion and the entire change becomes decorative — every
/// path from [`Lookup::Unanswerable`] to a positive verdict is a double-spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Lookup {
    /// A first occurrence, and this view is authoritative about it.
    Found(Occurrence),
    /// No record exists, in a view known to cover this asset's whole life.
    None,
    /// This view cannot answer — it starts too late, or it is mid-resync.
    /// **Never treat as `None`.**
    Unanswerable,
}

/// The chain view could not be read at all.
///
/// Distinct from [`Lookup::Unanswerable`], which is "my view does not reach
/// far enough"; this is "I could not ask". Carries the backend's own message
/// because that is what the user needs to fix the node.
#[derive(Debug)]
pub struct ChainViewError(pub String);

impl std::fmt::Display for ChainViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "chain view unavailable: {}", self.0)
    }
}

pub trait Chain {
    /// The first occurrence of `nf`, as far as this view can tell.
    fn first_occurrence(&self, nf: &Digest) -> Lookup;
    /// Current tip height.
    ///
    /// Fallible, because for a real backend it is an RPC — and the one caller
    /// that matters stamps an issuance floor from it. A backend that answered
    /// a failed call with a made-up height would stamp a wrong floor forever;
    /// a backend that panicked (as `uv-btc` used to) aborted `uv status` on a
    /// node hiccup. The caller decides which failures are fatal.
    fn tip(&self) -> Result<u64, ChainViewError>;

    /// How many times this view has had to undo part of itself after a reorg.
    ///
    /// Monotonic and **persisted by the backend**, because a wallet has to
    /// notice across process boundaries: every `uv` invocation is its own
    /// process, so an in-memory flag would be consumed by whichever command
    /// happened to trigger the scan and lost before the next one ran. A wallet
    /// compares this against the epoch it last reconciled at.
    ///
    /// Views that cannot reorg — the test double, the file-backed chain —
    /// return zero forever, which is the honest answer for them.
    fn rollback_epoch(&self) -> u64;

    /// Bring this view up to date with the chain before it is questioned.
    ///
    /// **Not optional, and the reason is a bug this actually had.** Reorg
    /// detection is lazy — it happens inside the first lookup. So a caller that
    /// reads [`Chain::rollback_epoch`] *before* doing any lookup reads a stale
    /// epoch, decides no reconciliation is owed, and only notices the reorg on
    /// the *next* invocation. The wallet was permanently one command behind the
    /// chain, and a regtest reorg caught it. Call this first.
    ///
    /// No default body, deliberately. Each of these three has a "safe-looking"
    /// answer — I see everything, I never reorged, nothing to refresh — that is
    /// in fact the fail-open one, and a default body hands it to any backend
    /// whose author simply did not think about it. That is the hole `Lookup`
    /// exists to close, one level up: there for the caller, here for the
    /// implementor.
    fn refresh(&self);

    /// The lowest height this view can answer for. Zero means it sees
    /// everything.
    ///
    /// A view whose floor sits above an asset's issuance cannot rule out an
    /// earlier conflicting record, and "I found nothing" from such a view is
    /// not the same statement as "nothing exists". Views that genuinely cover
    /// everything — the test double, the file-backed chain — return zero,
    /// explicitly. No default body: zero is the fail-open answer, and it should
    /// never be what a backend gets for writing no code.
    fn scan_floor(&self) -> u64;
    /// Publish a record. First occurrence wins: publishing a nullifier the
    /// chain already has is a no-op (and costs an attacker nothing — but
    /// gains them nothing either; see the signet demo).
    ///
    /// **Returns a `Result`, and that matters more than it looks.** This is
    /// called after a spend is signed. The Bitcoin backend used to `.expect()`
    /// here, so any RPC hiccup aborted the process at precisely the moment
    /// between a signature existing and it being safe to retry — turning
    /// "publish failed, try again" into "sign a second message with a one-time
    /// key". A failure has to be something the caller can hold.
    fn publish(&mut self, record: &Record) -> Result<(), PublishError>;

    /// Publish an issuance record: this much of an asset now exists.
    ///
    /// A separate method rather than a widened `publish`, because the two are
    /// different questions with different rules. A spend record is subject to
    /// first-occurrence — the second one for a nullifier is inert. An issuance
    /// record is *additive*: two of them mean two issuances, and the supply is
    /// the sum. Collapsing them into one call would invite the wrong rule.
    fn publish_issuance(&mut self, issuance: &Issuance) -> Result<(), PublishError>;

    /// Every confirmed issuance record this view can see, oldest first.
    ///
    /// **Filter by asset and the sum is that asset's supply, exactly.** Each
    /// record carries its asset id and genesis commitment in the clear, so an
    /// asset's issuances enumerate. This used to be an upper bound and nothing
    /// better: the record carried a one-way hash of those fields, which
    /// confirms a record you already know and enumerates nothing, so the only
    /// computable figure was a chain-wide sum over every asset and every
    /// stranger (`SPEC.md`).
    ///
    /// One residual for callers to respect: nothing authenticates an asset id,
    /// so a stranger may publish a **decoy** bearing someone else's. It creates
    /// no spendable coin — that needs a secret only the owner holds — but it
    /// bears the id, so `uv supply` reports records it can vouch for apart from
    /// ones it cannot rather than summing them together.
    fn issuances(&self) -> Vec<Issuance>;
}

/// An in-memory chain for tests: records confirm at the current tip.
#[derive(Default)]
pub struct MockChain {
    pub(crate) issuances: Vec<Issuance>,
    pub(crate) records: Vec<(Record, u64)>,
    pub(crate) tip: u64,
}

impl MockChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the tip by `n` blocks.
    pub fn mine(&mut self, n: u64) {
        self.tip += n;
    }

    /// Simulate a reorg dropping the record for `nf` entirely.
    pub fn reorg_drop(&mut self, nf: &Digest) {
        self.records.retain(|(r, _)| r.nullifier != *nf);
    }
}

impl Chain for MockChain {
    /// Never `Unanswerable`: this view *is* the whole chain by construction.
    /// That is a property of the test double, not something a real backend can
    /// claim.
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
        match self.records.iter().find(|(r, _)| r.nullifier == *nf) {
            Some((r, h)) => Lookup::Found(Occurrence {
                bundle_hash: r.bundle_hash,
                depth: self.tip.saturating_sub(*h) + 1,
            }),
            None => Lookup::None,
        }
    }

    fn tip(&self) -> Result<u64, ChainViewError> {
        Ok(self.tip)
    }

    fn publish(&mut self, record: &Record) -> Result<(), PublishError> {
        // Dedup is an optimisation, so an unanswerable view publishes anyway: a
        // duplicate costs a fee and first occurrence makes it inert, whereas
        // skipping a publish you could not check is a lost payment.
        if !matches!(self.first_occurrence(&record.nullifier), Lookup::Found(_)) {
            self.records.push((*record, self.tip));
        }
        Ok(())
    }

    fn publish_issuance(&mut self, issuance: &Issuance) -> Result<(), PublishError> {
        // Additive, not first-occurrence: two issuances are two issuances.
        self.issuances.push(*issuance);
        Ok(())
    }

    fn issuances(&self) -> Vec<Issuance> {
        self.issuances.clone()
    }

    // The three safety methods, stated rather than inherited — see the trait.
    fn rollback_epoch(&self) -> u64 {
        0 // an in-memory chain cannot reorganise behind our back
    }
    fn refresh(&self) {}
    fn scan_floor(&self) -> u64 {
        0 // this view *is* the whole chain
    }
}

/// A JSON-file-backed chain for local demos: the same first-occurrence rule,
/// persisted so separate CLI invocations share one view. Blocks advance
/// explicitly via [`FileChain::mine`], which is what makes confirmation-depth
/// behaviour demonstrable without a node.
pub struct FileChain {
    path: std::path::PathBuf,
    inner: MockChain,
}

#[derive(Serialize, Deserialize, Default)]
struct FileState {
    records: Vec<(Record, u64)>,
    /// Absent in files written before issuance records existed. `default` is
    /// right here and wrong for the index's `vout`: an empty issuance list on
    /// an old demo chain is *true* — none were ever published — whereas a
    /// defaulted position would claim knowledge the file never had.
    #[serde(default)]
    issuances: Vec<Issuance>,
    tip: u64,
}

impl FileChain {
    pub fn open(path: impl Into<std::path::PathBuf>) -> Self {
        let path = path.into();
        let st: FileState = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        FileChain {
            path,
            inner: MockChain {
                issuances: st.issuances,
                records: st.records,
                tip: st.tip,
            },
        }
    }

    fn save(&self) {
        let st = FileState {
            issuances: self.inner.issuances.clone(),
            records: self.inner.records.clone(),
            tip: self.inner.tip,
        };
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(bytes) = serde_json::to_vec(&st) {
            let _ = std::fs::write(&self.path, bytes);
        }
    }

    pub fn mine(&mut self, n: u64) {
        self.inner.mine(n);
        self.save();
    }
}

impl Chain for FileChain {
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
        self.inner.first_occurrence(nf)
    }
    fn tip(&self) -> Result<u64, ChainViewError> {
        self.inner.tip()
    }
    fn publish_issuance(&mut self, issuance: &Issuance) -> Result<(), PublishError> {
        self.inner.publish_issuance(issuance)?;
        self.save();
        Ok(())
    }
    fn issuances(&self) -> Vec<Issuance> {
        self.inner.issuances()
    }
    fn publish(&mut self, record: &Record) -> Result<(), PublishError> {
        self.inner.publish(record)?;
        self.save();
        Ok(())
    }
    fn rollback_epoch(&self) -> u64 {
        0 // a file-backed chain is rewritten, never reorganised
    }
    fn refresh(&self) {}
    fn scan_floor(&self) -> u64 {
        0 // the file holds every record there has ever been
    }
}

/// Confirmation depth required before a hop's settlement is trusted, scaled by
/// the value at stake. With amounts confidential, the receiver keys the policy
/// off the one amount it knows — the note being received.
///
/// **The floor is 3, not 1, and that is a correction.** `formal/reorg.qnt`
/// proves that at depth 1 against reorgs of up to 2 blocks the invariant
/// *everything I hold is still the first occurrence* is **violated**, and that
/// two independent repairs exist: wait deeper than the reorg you fear (module
/// `deep`), or reconcile when the chain reorganises (module `reconciled`).
/// This used to take the second option and say so here.
///
/// The second option did not work against the shipped Bitcoin backend when this
/// floor was raised: `btc`'s index stored no block hashes, never invalidated an
/// entry, and had no reorg detection, so after a reorg a withdrawn record was
/// still returned and its *depth grew*. That is now fixed — the index detects
/// divergence with a single block-hash comparison, rolls back to the fork, and
/// persists a rollback counter that `uv scan` and `uv send` reconcile against.
///
/// **The floor stays at 3 anyway, deliberately.** Restoring the
/// 1-confirmation tier is a separate decision that wants the regtest harness
/// first: the repair is now implemented and unit-tested, but it has not been
/// exercised against a real `bitcoind` performing a real reorg. Shipping the
/// implementation and lowering the floor in the same breath would be trusting
/// the fix on the strength of having written it.
/// **Decided 2026-07-28: three is the floor, and the 1-confirmation tier is not
/// coming back.** `spec/99 [SCAN-FLOOR]` left this open as "a policy decision
/// rather than a blocked one"; this is the decision.
///
/// `formal/reorg.qnt`'s `shallow` module *proves* depth-1 acceptance unsafe
/// against a 2-block reorg — not "risky", violated. Its `reconciled` module
/// proves reconciliation rescues that case, and reconciliation is now real and
/// exercised against a live `bitcoind`. So a 1-confirmation tier is safe **if
/// and only if** the receiver reconciles before relying on the money, and the
/// protocol cannot make them.
///
/// What the tier would buy is accepting a small payment ~20 minutes sooner.
/// What it risks is money that evaporates for a receiver who did the ordinary
/// thing. That trade is not worth taking to shave two blocks off a payment
/// whose whole premise is settling on Bitcoin, so the tier stays withdrawn and
/// this stops being an open question.
pub fn required_confirmations(value: u64) -> u64 {
    if value < 100_000 {
        3
    } else {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    fn d(t: u32) -> Digest {
        [BabyBear::from_u32(t); 8]
    }

    #[test]
    fn first_occurrence_wins_and_republish_is_inert() {
        let mut c = MockChain::new();
        c.mine(10);
        c.publish(&Record {
            nullifier: d(1),
            bundle_hash: d(2),
        })
        .unwrap();
        c.mine(1);
        // A later record for the same nullifier changes nothing.
        c.publish(&Record {
            nullifier: d(1),
            bundle_hash: d(9),
        })
        .unwrap();
        let Lookup::Found(occ) = c.first_occurrence(&d(1)) else {
            panic!("a published record must be found")
        };
        assert_eq!(occ.bundle_hash, d(2));
        assert_eq!(occ.depth, 2, "published at 10, tip 11");
    }

    #[test]
    fn confirmation_tiers() {
        // The floor is 3, not 1: `formal/reorg.qnt` proves depth 1 is violated
        // by a 2-block reorg, and the repair that would have allowed depth 1
        // does not function against the real chain backend. See the doc
        // comment on `required_confirmations`.
        assert_eq!(required_confirmations(1), 3);
        assert_eq!(required_confirmations(999), 3);
        assert_eq!(required_confirmations(1_000), 3);
        assert_eq!(required_confirmations(99_999), 3);
        assert_eq!(required_confirmations(100_000), 6);
        assert_eq!(required_confirmations(u64::MAX), 6);
    }
}
