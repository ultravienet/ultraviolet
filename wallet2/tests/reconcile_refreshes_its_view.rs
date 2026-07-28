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
use uv_wallet2::reconcile::reconcile;
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
}

impl StaleChain {
    fn new() -> Self {
        StaleChain {
            records: RefCell::new(Vec::new()),
            tip: 0,
            pending_drop: RefCell::new(None),
            refreshed: Cell::new(false),
        }
    }
}

impl Chain for StaleChain {
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
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

    let out = reconcile(&chain, &mut store, &log);
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

    let out = reconcile(&chain, &mut store, &log);

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
