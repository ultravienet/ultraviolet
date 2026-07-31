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
    /// Notes that were quarantined and now settle again, cleanly — every hop
    /// found, matching, and deep enough. Released.
    pub restored: Vec<[u8; 32]>,
    /// Notes the chain view could not answer for. **Deliberately left
    /// alone** — see [`reconcile`].
    pub unverifiable: Vec<[u8; 32]>,
}

/// Re-validate settlement for every held note.
///
/// **On an unanswerable view, nothing changes state.** Treating "I cannot see
/// far enough back" as "this is bad" would let a node that is merely mid-resync
/// freeze the user's money. Those notes are returned
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
/// What this wallet's asset was issued as, for the genesis half of the pass.
///
/// `None` means the caller has no anchor opening — an anchor written before
/// issuance went on chain — and the genesis check is skipped, exactly as
/// [`crate::accept::accept`] skips it.
pub struct Genesis<'a> {
    pub asset: &'a uv_air::poseidon2::Digest,
    pub commitment: &'a uv_air::poseidon2::Digest,
    pub amount: u64,
}

pub fn reconcile(
    chain: &(impl Chain + ?Sized),
    store: &mut Store,
    log: &SignLog,
    genesis: Option<&Genesis<'_>>,
) -> Reconciled {
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
    let mut restored = Vec::new();
    let mut unverifiable = Vec::new();

    // **The genesis half.** `accept` refuses a coin whose issuance is not on
    // the chain it is reading; this is the same question asked again after the
    // chain moves. Without it the rule held only at the moment of acceptance:
    // a reorg that orphans the issuance while the spend records survive — or
    // are re-mined, which is the ordinary outcome — left every note in place,
    // backed by an issuance no reader of Bitcoin can find. That is precisely
    // the state the whole supply argument says cannot exist.
    //
    // Failing this condemns *every* note of the asset, which is right and not
    // a blunt instrument: if the issuance is gone then nothing descending from
    // it is money, whatever its own hops did.
    //
    // Quarantine, never deletion, and it releases again on its own: the far
    // more likely cause is a view that has not caught up or a record about to
    // be re-mined. `reorgs_on_a_real_node.rs` case 1 is the reorg where everything
    // comes back.
    // The same three byte comparisons `accept` makes, asked of the chain as it
    // stands now rather than as it stood at acceptance.
    let genesis_gone = match genesis {
        None => false,
        Some(g) => !chain
            .issuances()
            .iter()
            .any(|i| i.asset == *g.asset && i.commitment == *g.commitment && i.amount == g.amount),
    };

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

    // Quarantined notes are re-examined too, so the door can open again.
    //
    // It used to be one-way: a reorg that orphaned a record quarantined the
    // note, and when the very same record was re-mined — the ordinary outcome,
    // and exactly what `reorgs_on_a_real_node.rs` case 1 exercises — nothing ever
    // looked again. A note that is demonstrably good stayed frozen forever.
    //
    // The restore condition is the **full positive check**, identical to the
    // one that keeps an unspent note: every hop found, bundle matching, deep
    // enough. Never "the failing check stopped failing" — a note that
    // un-quarantines on a weaker test than it was condemned by is a note that
    // can be spent twice.
    let to_check: Vec<_> = store
        .iter()
        .filter(|h| {
            matches!(
                h.state,
                NoteState::Unspent | NoteState::InFlight | NoteState::Quarantined
            )
        })
        .map(|h| {
            (
                h.note.commitment(),
                h.note.amount.0,
                h.lineage.clone(),
                h.state,
            )
        })
        .collect();

    for (commitment, value, lineage, was) in to_check {
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
        if genesis_gone {
            // Before the per-hop verdict, and not folded into it: a note whose
            // issuance vanished is condemned by the asset, not by its own
            // ancestry, and reporting it as an ancestry failure would send
            // whoever reads the output looking in the wrong place.
            if was != NoteState::Quarantined {
                store
                    .set_state(&commitment, NoteState::Quarantined)
                    .expect("iterated out of this very store");
                quarantined.push(digest::encode(&commitment));
            }
        } else if blind {
            // Inconclusive. A quarantined note stays quarantined — "I cannot
            // tell" is not grounds to release it, only to say so.
            unverifiable.push(digest::encode(&commitment));
        } else if !still_good {
            if was != NoteState::Quarantined {
                store
                    .set_state(&commitment, NoteState::Quarantined)
                    .expect("iterated out of this very store");
                quarantined.push(digest::encode(&commitment));
            }
        } else if was == NoteState::Quarantined {
            // Every hop settled, matched and deep — the same bar an unspent
            // note must clear. Restore to `Unspent` and not to `InFlight`:
            // whether a spend of *this* note is in flight is the sign-log's
            // question, and a reorg does not answer it.
            store
                .set_state(&commitment, NoteState::Unspent)
                .expect("iterated out of this very store");
            restored.push(digest::encode(&commitment));
        }
    }
    Reconciled {
        quarantined,
        restored,
        unverifiable,
    }
}
