//! Regression test: `reconcile` brings its chain view up to date before
//! judging anything.
//!
//! **Why this needs its own chain double.** `reconcile.rs` calls
//! `chain.refresh()` first, and for a while that line carried a comment
//! admitting it was *not observable*: deleting it left the whole suite green,
//! including `demo/regtest.sh` against a real bitcoind — because `uv-btc`'s
//! `first_occurrence` happens to index forward to the tip on every lookup, so
//! any wallet with notes to check refreshed as a side effect. A safety call
//! that no test can see failing is one refactor away from being deleted as
//! dead code, and the deletion would be invisible until a backend whose
//! lookups do *not* self-refresh shipped.
//!
//! So this double is exactly that backend: a chain whose reorg lands only
//! when `refresh()` is called, the way `uv-btc`'s *detection* works — it is
//! lazy, and somebody has to ask. `MockChain` cannot express this; its
//! lookups are always live.
//!
//! The test would have failed before `refresh()` moved inside `reconcile`,
//! and fails today if that line is deleted. Checked by deleting it.

use std::cell::{Cell, RefCell};

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

use uv_air::wots::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer::Transfer;
use uv_wallet2::accept::Hop;
use uv_wallet2::chain::{Chain, ChainViewError, Lookup, Occurrence, PublishError};
use uv_wallet2::reconcile::{reconcile, Genesis};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

/// A chain view that answers from a snapshot until `refresh()` is called.
///
/// `pending_drop` is a reorg that has already happened on the network but that
/// this view has not noticed yet — the state a real backend is in between the
/// reorg and its next detection pass.
struct StaleChain {
    records: RefCell<Vec<(Record, u64)>>,
    tip: u64,
    pending_drop: RefCell<Option<Digest>>,
    refreshed: Cell<bool>,
    /// When set, every lookup answers `Unanswerable` — a node mid-resync.
    blind: Cell<bool>,
    /// Issuance records this view can see. A reorg can orphan one of these
    /// just as easily as a spend record.
    issuances: RefCell<Vec<uv_kernel2::issuance::Issuance>>,
}

impl StaleChain {
    fn new() -> Self {
        StaleChain {
            records: RefCell::new(Vec::new()),
            tip: 0,
            pending_drop: RefCell::new(None),
            refreshed: Cell::new(false),
            blind: Cell::new(false),
            issuances: RefCell::new(Vec::new()),
        }
    }
}

impl Chain for StaleChain {
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
        if self.blind.get() {
            return Lookup::Unanswerable;
        }
        // Deliberately does NOT apply the pending reorg: lookups answer from
        // the stale snapshot, which is the whole point of the double.
        match self
            .records
            .borrow()
            .iter()
            .find(|(r, _)| r.nullifier == *nf)
        {
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
        self.records.borrow_mut().push((*record, self.tip));
        Ok(())
    }
    fn publish_issuance(&mut self, _: &uv_kernel2::issuance::Issuance) -> Result<(), PublishError> {
        Ok(())
    }
    fn issuances(&self) -> Vec<uv_kernel2::issuance::Issuance> {
        self.issuances.borrow().clone()
    }
    fn rollback_epoch(&self) -> u64 {
        u64::from(self.refreshed.get())
    }
    fn refresh(&self) {
        self.refreshed.set(true);
        if let Some(nf) = self.pending_drop.borrow_mut().take() {
            self.records.borrow_mut().retain(|(r, _)| r.nullifier != nf);
        }
    }
    fn scan_floor(&self) -> u64 {
        0
    }
}

/// A wallet holding one note whose single-hop lineage settled on `chain`.
fn wallet_with_settled_note(chain: &mut StaleChain) -> (Store, SignLog, Digest, Digest) {
    let seed = WalletSeed([3u8; 32]);
    let mut store = Store::default();
    let key_index = store.allocate_index();
    let keys = derive(&seed, key_index);
    let asset = [BabyBear::from_u32(0xA5); 8];
    let note = Note::build(asset, Amount(50), &keys);
    let commitment = note.commitment();

    // The hop that paid this note. `reconcile` reads only the nullifier and
    // the bundle hash, so the transfer needs the right shape, not a proof.
    let transfer = Transfer {
        input_commitment: [BabyBear::from_u32(1); 8],
        nullifier: [BabyBear::from_u32(2); 8],
        outputs: vec![commitment, [BabyBear::from_u32(4); 8]],
        prev_history: [BabyBear::ZERO; 8],
    };
    let nf = transfer.nullifier;
    let record = Record {
        nullifier: nf,
        bundle_hash: transfer.bundle_hash(),
    };
    chain.publish(&record).expect("mock publish");
    chain.tip += 5; // deep enough for the sub-100k tier's 3 confirmations

    store
        .insert(Held {
            note,
            key_index,
            lineage: vec![Hop {
                transfer,
                proof: Vec::new(),
            }],
            state: NoteState::Unspent,
        })
        .expect("fresh store");
    (store, SignLog::default(), commitment, nf)
}

/// The control: with no reorg pending, reconcile confirms the note is fine.
#[test]
fn a_settled_note_survives_reconciliation() {
    let mut chain = StaleChain::new();
    let (mut store, log, commitment, _nf) = wallet_with_settled_note(&mut chain);

    let out = reconcile(&chain, &mut store, &log, None);
    assert!(out.quarantined.is_empty(), "nothing to quarantine");
    assert!(out.unverifiable.is_empty());
    assert_eq!(store.get(&commitment).unwrap().state, NoteState::Unspent);
}

/// The pin: a reorg the view has not noticed yet must still be noticed by
/// `reconcile`, because `reconcile` refreshes before judging. Delete the
/// `chain.refresh()` inside `reconcile` and this fails — the note survives on
/// stale evidence.
#[test]
fn reconcile_notices_a_reorg_its_view_has_not_seen_yet() {
    let mut chain = StaleChain::new();
    let (mut store, log, commitment, nf) = wallet_with_settled_note(&mut chain);

    // The network reorganised the record away; this view does not know yet.
    *chain.pending_drop.borrow_mut() = Some(nf);
    assert!(
        matches!(chain.first_occurrence(&nf), Lookup::Found(_)),
        "precondition: the stale view still shows the record"
    );

    let out = reconcile(&chain, &mut store, &log, None);

    assert!(
        chain.refreshed.get(),
        "reconcile must refresh the view before judging"
    );
    assert_eq!(
        out.quarantined.len(),
        1,
        "the orphaned note must quarantine — passing here on stale evidence \
         is exactly the failure this test exists to catch"
    );
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Quarantined
    );
}

/// **Quarantine is not a one-way door — but the way out is the full check.**
///
/// A reorg that orphans a record quarantines the note. The ordinary sequel is
/// that the very same record is re-mined at a new height (`demo/regtest.sh`
/// case 1 is exactly this), and before this existed nothing ever looked again:
/// a note that was demonstrably good stayed frozen for ever.
///
/// What must NOT happen is release on a weaker test than the one that
/// condemned it — "the failing check stopped failing" would let a note
/// un-quarantine itself into being spendable twice. So the bar is identical to
/// the one an unspent note clears: every hop found, bundle matching, deep
/// enough.
#[test]
fn a_quarantined_note_is_released_only_by_the_full_positive_check() {
    let mut chain = StaleChain::new();
    let (mut store, log, commitment, nf) = wallet_with_settled_note(&mut chain);

    // The reorg lands, and the note is quarantined.
    *chain.pending_drop.borrow_mut() = Some(nf);
    let out = reconcile(&chain, &mut store, &log, None);
    assert_eq!(out.quarantined.len(), 1, "the orphaned note quarantines");
    assert!(out.restored.is_empty());
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Quarantined
    );

    // An inconclusive pass must NOT release it. "I cannot tell" is grounds to
    // report, never to hand the money back.
    chain.blind.set(true);
    let out = reconcile(&chain, &mut store, &log, None);
    assert!(
        out.restored.is_empty(),
        "an unanswerable view released a quarantined note"
    );
    assert_eq!(
        out.unverifiable.len(),
        1,
        "and it should say it could not tell"
    );
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Quarantined
    );
    chain.blind.set(false);

    // The record is re-mined — the common case — and now the full check passes.
    chain.records.borrow_mut().push((
        uv_kernel2::record::Record {
            nullifier: nf,
            bundle_hash: store.get(&commitment).unwrap().lineage[0]
                .transfer
                .bundle_hash(),
        },
        0,
    ));
    let out = reconcile(&chain, &mut store, &log, None);
    assert_eq!(
        out.restored.len(),
        1,
        "a re-mined record must free the note"
    );
    assert!(out.quarantined.is_empty());
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Unspent,
        "released to Unspent — whether a spend is in flight is the sign-log's \
         question, and a reorg does not answer it"
    );
}

/// **A reorg that orphans the issuance itself.**
///
/// Every hop still settles — the spend records survived, or were re-mined,
/// which is the ordinary outcome. Only the 44-byte issuance record is gone.
/// `accept` refuses such a coin at the door; before this, `reconcile` re-ran
/// only the settlement half, so a note already held stayed held and the wallet
/// went on believing in an issuance no reader of Bitcoin can find. That is
/// exactly the state spec/12's whole argument says cannot exist.
#[test]
fn a_note_whose_issuance_was_orphaned_is_quarantined() {
    use p3_field::PrimeCharacteristicRing;
    let mut chain = StaleChain::new();
    let (mut store, log, commitment, _nf) = wallet_with_settled_note(&mut chain);

    let asset = [p3_baby_bear::BabyBear::from_u32(5); 8];
    let gc = [p3_baby_bear::BabyBear::from_u32(6); 8];
    let genesis = Genesis {
        asset: &asset,
        commitment: &gc,
        amount: 1000,
    };

    // The control FIRST. With the issuance confirmed, this exact setup leaves
    // the note alone — so the quarantine below is the genesis check and not
    // some unrelated thing about this fixture.
    chain
        .issuances
        .borrow_mut()
        .push(uv_kernel2::issuance::Issuance {
            amount: 1000,
            asset,
            commitment: gc,
        });
    let out = reconcile(&chain, &mut store, &log, Some(&genesis));
    assert!(
        out.quarantined.is_empty(),
        "control: a confirmed issuance must leave the note alone"
    );
    assert_eq!(store.get(&commitment).unwrap().state, NoteState::Unspent);

    // Now the reorg takes the issuance record and nothing else.
    chain.issuances.borrow_mut().clear();
    let out = reconcile(&chain, &mut store, &log, Some(&genesis));
    assert_eq!(
        out.quarantined.len(),
        1,
        "an orphaned issuance must condemn the coins that descend from it"
    );
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Quarantined
    );

    // And it releases when the record comes back — the far likelier cause is a
    // view behind the tip or a record about to be re-mined, so this must not
    // be a one-way door.
    chain
        .issuances
        .borrow_mut()
        .push(uv_kernel2::issuance::Issuance {
            amount: 1000,
            asset,
            commitment: gc,
        });
    let out = reconcile(&chain, &mut store, &log, Some(&genesis));
    assert_eq!(out.restored.len(), 1, "a re-mined issuance must release it");
    assert_eq!(store.get(&commitment).unwrap().state, NoteState::Unspent);
}

/// An issuance of the right AMOUNT but for a different genesis must not
/// rescue a note — the same free-mint hole the accept path had, which would
/// have been re-opened here if this check had been written as a sum.
#[test]
fn another_assets_issuance_does_not_rescue_a_quarantined_note() {
    use p3_field::PrimeCharacteristicRing;
    let mut chain = StaleChain::new();
    let (mut store, log, commitment, _nf) = wallet_with_settled_note(&mut chain);

    let asset = [p3_baby_bear::BabyBear::from_u32(5); 8];
    let gc = [p3_baby_bear::BabyBear::from_u32(6); 8];
    let other = [p3_baby_bear::BabyBear::from_u32(9); 8];
    // Somebody else's issuance, same amount.
    chain
        .issuances
        .borrow_mut()
        .push(uv_kernel2::issuance::Issuance {
            amount: 1000,
            asset: other,
            commitment: other,
        });
    let out = reconcile(
        &chain,
        &mut store,
        &log,
        Some(&Genesis {
            asset: &asset,
            commitment: &gc,
            amount: 1000,
        }),
    );
    assert_eq!(
        out.quarantined.len(),
        1,
        "an amount match is not this asset"
    );
    assert_eq!(
        store.get(&commitment).unwrap().state,
        NoteState::Quarantined
    );
}
