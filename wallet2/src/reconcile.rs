//! Reorg reconciliation: re-check what you hold when the chain changes.
//!
//! `formal/reorg.qnt`: with 1-confirmation acceptance and no rollback, the
//! invariant "everything I hold is still the first occurrence" is violated by
//! a 2-block reorg — and the wallet never finds out. Two proven fixes: wait
//! deeper, or **reconcile on reorg**. The confirmation tiers make small
//! payments fast, so the small-payment tier leans entirely on this module.
//!
//! Reconciliation re-runs the settlement half of acceptance over every held
//! note's lineage. A note whose ancestry no longer settles is **quarantined**
//! — not deleted: the honest record may reconfirm, and if this wallet made
//! the losing spend itself, recovery is the sign-log replay, never a new
//! signature.

use uv_kernel2::digest;

use crate::chain::{required_confirmations, Chain, Lookup, Occurrence};
use crate::signlog::SignLog;
use crate::store::{NoteState, Store};

/// What a reconciliation pass concluded.
#[derive(Debug, Default)]
pub struct Reconciled {
    /// Notes whose ancestry no longer settles. Quarantined.
    pub quarantined: Vec<[u8; 32]>,
    /// Notes the chain view could not answer for. **Deliberately left
    /// alone** — see [`reconcile`].
    pub unverifiable: Vec<[u8; 32]>,
}

/// Re-validate settlement for every held note.
///
/// **On an unanswerable view, nothing changes state.** Quarantine is currently
/// a one-way door — nothing ever un-quarantines a note — so treating "I cannot
/// see far enough back" as "this is bad" would let a node that is merely
/// mid-resync permanently freeze the user's money. Those notes are returned
/// separately instead, for the caller to report loudly. Leaving state alone is
/// safe because it is `accept` that decides whether a note may be *taken*, and
/// `accept` refuses an unanswerable view outright.
///
/// Also promotes in-flight notes whose own spend has settled to `Spent`: the
/// wallet's view of its own money converges on the chain's, and a note that
/// is genuinely gone stops looking like one awaiting rebroadcast. That
/// distinction is the whole point of `onetime.qnt`'s `settled` set — refusing
/// to re-sign a settled note is correctness, while a signed-but-unsettled note
/// is the one that needs the replay path.
pub fn reconcile(chain: &(impl Chain + ?Sized), store: &mut Store, log: &SignLog) -> Reconciled {
    // Inside, not at the call site. Its doc says "not optional", and
    // `cmd_reconcile` still forgot — getting away with it only because the
    // first lookup refreshes as a side effect, which fails when there is
    // nothing to look up. A rule enforced by remembering is not enforced.
    //
    // Pinned by `tests/reconcile_refreshes_its_view.rs`, whose chain double
    // answers from a stale snapshot until refreshed — the state a real backend
    // is in between a reorg and its next detection pass. It had to be a
    // purpose-built double: against `uv-btc` deleting this line changes
    // nothing, because that backend's `first_occurrence` indexes to the tip on
    // every lookup. Verified by deleting the line and watching the test fail.
    chain.refresh();

    let mut quarantined = Vec::new();
    let mut unverifiable = Vec::new();

    // In-flight notes whose own record settled are spent, not in flight.
    let inflight: Vec<_> = store
        .iter()
        .filter(|h| h.state == NoteState::InFlight)
        .map(|h| (h.note.commitment(), h.key_index))
        .collect();
    for (commitment, key_index) in inflight {
        if let Some(spend) = log.get(key_index) {
            let bundle = spend.transfer.bundle_hash();
            // Only a positive, authoritative answer promotes a note to Spent.
            if let Lookup::Found(occ) = chain.first_occurrence(&spend.transfer.nullifier) {
                if occ.bundle_hash == bundle && occ.depth >= 1 {
                    // Every commitment in this pass came from `store.iter()`
                    // and the store has no removal path, so the lookup cannot
                    // miss. Said out loud rather than swallowed.
                    store
                        .set_state(&commitment, NoteState::Spent)
                        .expect("iterated out of this very store");
                }
            }
        }
    }

    let to_check: Vec<_> = store
        .iter()
        .filter(|h| matches!(h.state, NoteState::Unspent | NoteState::InFlight))
        .map(|h| (h.note.commitment(), h.note.amount.0, h.lineage.clone()))
        .collect();

    for (commitment, value, lineage) in to_check {
        let required = required_confirmations(value);
        let mut blind = false;
        let still_good = lineage.iter().all(|hop| {
            let bundle = hop.transfer.bundle_hash();
            match chain.first_occurrence(&hop.transfer.nullifier) {
                Lookup::Found(Occurrence { bundle_hash, depth }) => {
                    bundle_hash == bundle && depth >= required
                }
                Lookup::None => false,
                Lookup::Unanswerable => {
                    blind = true;
                    // Not a judgement either way. `still_good` stays true so
                    // this hop does not itself condemn the note; `blind`
                    // records that the pass was not conclusive.
                    true
                }
            }
        });
        if blind {
            unverifiable.push(digest::encode(&commitment));
        } else if !still_good {
            store
                .set_state(&commitment, NoteState::Quarantined)
                .expect("iterated out of this very store");
            quarantined.push(digest::encode(&commitment));
        }
    }
    Reconciled {
        quarantined,
        unverifiable,
    }
}
