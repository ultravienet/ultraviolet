//! Read-only commands over an opened wallet, shared by the CLI and the app.
//!
//! The rule of this crate applies (`lib.rs`): return a value, never print,
//! never exit. These are the questions both callers ask a wallet; each caller
//! renders the answer its own way — a terminal in columns, a phone in a list.

use uv_kernel2::digest;
use uv_wallet2::store::NoteState;

use crate::wallet::Wallet;

/// One held note, as a caller displays it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NoteLine {
    pub state: NoteState,
    pub amount: u64,
    /// Hex of the note commitment — the note's public name.
    pub commitment_hex: String,
}

/// What `balance` answers: the spendable total, and every note with its state.
///
/// `spendable` counts **`Unspent` only**. In-flight notes are already spoken
/// for, quarantined notes may never come back, and spent notes are gone — a
/// balance that included any of them would be a number the user cannot spend,
/// which is the only kind of wrong a balance can be.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Balance {
    pub spendable: u64,
    pub notes: Vec<NoteLine>,
}

/// The wallet's balance, from local state alone.
///
/// Deliberately touches no chain: this answers "what does my wallet think",
/// in milliseconds, offline. Why the chain might disagree — a reorg nobody
/// reconciled, a view that cannot see far enough — is `status`'s job, which
/// exists precisely because this command cannot distinguish those cases.
pub fn balance(wallet: &Wallet) -> Balance {
    let mut spendable = 0u64;
    let mut notes = Vec::new();
    for h in wallet.store.iter() {
        if h.state == NoteState::Unspent {
            spendable += h.note.amount.0;
        }
        notes.push(NoteLine {
            state: h.state,
            amount: h.note.amount.0,
            commitment_hex: hex::encode(digest::encode(&h.note.commitment())),
        });
    }
    Balance { spendable, notes }
}

/// One in-flight note's settlement verdict, as the chain answers it now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum InFlightVerdict {
    /// A record exists and matches; how deep it is against how deep it must be.
    Confirmations { depth: u64, need: u64 },
    /// No record on chain yet.
    NoRecord,
    /// This chain view cannot say.
    Unanswerable,
    /// The sign-log has no payload for a note marked in flight — a state the
    /// wallet should make impossible, reported rather than papered over.
    LogMissingPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InFlightLine {
    pub amount: u64,
    pub verdict: InFlightVerdict,
}

/// The note tally: counts per state, and the spendable sum (Unspent only —
/// same rule as [`balance`], stated once there).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct NoteTally {
    pub unspent: u64,
    pub in_flight: u64,
    pub spent: u64,
    pub quarantined: u64,
    pub spendable: u64,
}

/// A handed-out slot batch, with how many of its slots have been paid so far.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BatchLine {
    pub first: u64,
    pub count: u64,
    pub peer: Option<String>,
    pub used: u64,
}

/// What the trust anchor says, or why it could not be read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum AnchorLine {
    /// No anchor.json — this wallet cannot validate anything.
    Absent,
    /// The file exists but does not parse; the message says why. **Not the
    /// same as absent**: an unreadable trust root must be seen, not skipped.
    Unreadable(String),
    Present {
        asset_hex: String,
        /// `None` = an anchor written before floors existed ("unknown").
        issued_below: Option<u64>,
    },
}

/// Everything `status` answers: why the money is or is not where expected.
///
/// Every chain question degrades rather than aborts — a node that is down
/// produces a report saying so, not no report at all. That is why `tip` is a
/// `Result`-shaped pair rather than this function failing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Status {
    /// The wallet's own scan-key fingerprint — what a payer's reservation file
    /// is named after, readable aloud to confirm two people hold one address.
    pub address_id: String,
    pub tip: std::result::Result<u64, String>,
    pub scan_floor: u64,
    pub rollback_epoch: u64,
    pub anchor: AnchorLine,
    pub notes: NoteTally,
    pub in_flight: Vec<InFlightLine>,
    pub batches: Vec<BatchLine>,
    /// Payments set aside with no free slot to sit in, counted per *home* —
    /// the drop box is one shared directory, so this cannot tell whose payment
    /// it is without trial-decapsulating on every wallet's behalf.
    pub stuck: usize,
    pub stuck_dir: std::path::PathBuf,
}

/// The full report. `wallet_name` picks the batch ledger; the chain answers
/// what it can and the report carries what it could not.
pub fn status(
    home: &std::path::Path,
    wallet_name: &str,
    wallet: &Wallet,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
) -> Status {
    use uv_wallet2::chain::{required_confirmations, Lookup};

    let (_, scan) = uv_envelope::derive_scan(&wallet.seed.0);
    let address_id = crate::slots::address_id(&scan.x25519_hex, &scan.ml_kem_hex);

    let anchor = match crate::anchor::read(home) {
        Ok(None) => AnchorLine::Absent,
        Err(e) => AnchorLine::Unreadable(e.to_string()),
        Ok(Some(a)) => AnchorLine::Present {
            asset_hex: a.asset_hex,
            issued_below: a.issued_below,
        },
    };

    let mut notes = NoteTally::default();
    for h in wallet.store.iter() {
        match h.state {
            NoteState::Unspent => {
                notes.unspent += 1;
                notes.spendable += h.note.amount.0;
            }
            NoteState::InFlight => notes.in_flight += 1,
            NoteState::Spent => notes.spent += 1,
            NoteState::Quarantined => notes.quarantined += 1,
        }
    }

    // In-flight notes are the ones a person is usually waiting on, so say
    // exactly what the chain thinks of each rather than making them guess.
    let in_flight = wallet
        .store
        .iter()
        .filter(|h| h.state == NoteState::InFlight)
        .map(|h| InFlightLine {
            amount: h.note.amount.0,
            verdict: match wallet.log.get(h.key_index) {
                None => InFlightVerdict::LogMissingPayload,
                Some(s) => match chain.first_occurrence(&s.transfer.nullifier) {
                    Lookup::Found(o) => InFlightVerdict::Confirmations {
                        depth: o.depth,
                        need: required_confirmations(h.note.amount.0),
                    },
                    Lookup::None => InFlightVerdict::NoRecord,
                    Lookup::Unanswerable => InFlightVerdict::Unanswerable,
                },
            },
        })
        .collect();

    // Which slot batches are outstanding, so replenishment is answerable. The
    // payee cannot see which slots a payer has consumed — that state is
    // payer-local by design — so this reports what was handed out, and how
    // many of each batch's slots this wallet has been paid on.
    let batches = crate::batches::read(home, wallet_name)
        .into_iter()
        .map(|b| BatchLine {
            used: wallet
                .store
                .iter()
                .filter(|h| h.key_index >= b.first && h.key_index < b.first + b.count)
                .count() as u64,
            first: b.first,
            count: b.count,
            peer: b.peer,
        })
        .collect();

    let stuck_dir = crate::home::unplaceable_dir(home);
    let stuck = std::fs::read_dir(&stuck_dir)
        .into_iter()
        .flatten()
        .flatten()
        .count();

    Status {
        address_id,
        tip: chain.tip().map_err(|e| e.to_string()),
        scan_floor: chain.scan_floor(),
        rollback_epoch: chain.rollback_epoch(),
        anchor,
        notes,
        in_flight,
        batches,
        stuck,
        stuck_dir,
    }
}

/// One issuance record, as `supply` reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IssuanceLine {
    pub amount: u64,
    pub commitment_hex: String,
    /// Whether this home's own anchor vouches for the record — same asset,
    /// same genesis commitment, same amount, byte for byte.
    pub attested: bool,
}

/// One asset's supply: its records, and the attested/unattested split.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AssetSupply {
    pub asset_hex: String,
    pub records: Vec<IssuanceLine>,
    pub total: u64,
    pub attested: u64,
}

/// What `supply` answers: per-asset totals read off the chain, split by
/// whether this home can vouch for each record.
///
/// Nothing authenticates an asset id, so anyone may publish a record bearing
/// one — it creates no spendable coin (no one holds a note opening to its
/// genesis), but it inflates a naive sum. Keeping attested and unattested
/// apart is the whole design of this report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Supply {
    pub assets: Vec<AssetSupply>,
}

/// Count supply off the chain, exactly.
///
/// Refreshes the view first: the Bitcoin backend's issuance list is built by
/// scanning, so without this a freshly-issued asset reads as "no issuance
/// records" on the very node that just published it — not a wrong number, a
/// confidently wrong one, and this command exists to be believed.
///
/// A home with no anchor (or an unreadable one) vouches for nothing, which is
/// honest rather than a failure. `filter` narrows to one asset id (lowercase
/// hex); an unknown id yields an empty report, which the caller distinguishes
/// from "no records at all" by having asked.
pub fn supply(
    home: &std::path::Path,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
    filter: Option<&str>,
) -> Supply {
    chain.refresh();
    let mut issuances = chain.issuances();
    if let Some(want) = filter {
        let want = want.to_ascii_lowercase();
        issuances.retain(|i| hex::encode(digest::encode(&i.asset)) == want);
    }

    let mine = crate::anchor::read(home).ok().flatten();
    let attested = |i: &uv_kernel2::issuance::Issuance| -> bool {
        mine.as_ref().is_some_and(|a| {
            hex::encode(digest::encode(&i.asset)) == a.asset_hex
                && hex::encode(digest::encode(&i.commitment)) == a.commitment_hex
                && i.amount == a.genesis.amount
        })
    };

    let mut asset_ids: Vec<String> = issuances
        .iter()
        .map(|i| hex::encode(digest::encode(&i.asset)))
        .collect();
    asset_ids.sort();
    asset_ids.dedup();

    let assets = asset_ids
        .into_iter()
        .map(|a| {
            let records: Vec<IssuanceLine> = issuances
                .iter()
                .filter(|i| hex::encode(digest::encode(&i.asset)) == a)
                .map(|i| IssuanceLine {
                    amount: i.amount,
                    commitment_hex: hex::encode(digest::encode(&i.commitment)),
                    attested: attested(i),
                })
                .collect();
            let total = records.iter().map(|r| r.amount).sum();
            let attested_sum = records
                .iter()
                .filter(|r| r.attested)
                .map(|r| r.amount)
                .sum();
            AssetSupply {
                asset_hex: a,
                records,
                total,
                attested: attested_sum,
            }
        })
        .collect();

    Supply { assets }
}

/// The reorg margin the issuance floor is stamped under: tip minus this, never
/// the bare tip — the tip at issue time can itself be reorged away, and a
/// record could then land below the floor. Off by one reorg is a silent
/// fail-open, which is why the number is the index's own reorg window.
pub const REORG_MARGIN: u64 = uv_btc::index::REORG_WINDOW as u64;

/// An issuance that is in the wallet but **not yet on chain**.
///
/// The type exists to make an ordering impossible to get wrong, the same shape
/// as `wallet2::send::PreparedSpend`: the note and its consumed index must be
/// durable before the record is published — a crash between leaves a published
/// genesis no wallet remembers owning. `prepare_issue` takes no publishing
/// chain method and cannot publish; [`publish_issue`] consumes this and does
/// nothing else. The caller's save goes between them.
#[must_use = "a prepared issuance is in the wallet but not on chain; persist the wallet, then publish it"]
pub struct PreparedIssue {
    issuance: uv_kernel2::issuance::Issuance,
    anchor: crate::anchor::Anchor,
}

/// What `issue` reports once the record is on chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Issued {
    pub amount: u64,
    pub asset_hex: String,
    pub commitment_hex: String,
}

/// Stage an issuance: floor preflight, then the note into the wallet.
///
/// **The floor is read before anything is written**, so a node that cannot
/// answer leaves no trace — everything that can refuse, refuses before
/// anything is committed. Refusing rather than stamping `None` from a failed
/// call is deliberate: an anchor's floor is permanent, and `None` would
/// silently weaken the asset forever. The issuance is simply retried when the
/// node is back.
///
/// The asset id is the issuance note's own **owner key** — public by nature,
/// deterministic, and unforgeable without the issuer's seed. It must never be
/// a secret key: the anchor publishes the asset id to every payee, and an
/// asset id that doubled as the genesis note's nullifier key or anchor
/// preimage would let anyone with an anchor kill or spend the genesis
/// (pinned by `wallet2/tests/an_anchor_does_not_reveal_the_genesis_nullifier.rs`).
pub fn prepare_issue(
    wallet: &mut Wallet,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
    amount: u64,
) -> crate::Result<PreparedIssue> {
    use uv_kernel2::amount::Amount;
    use uv_kernel2::keys::derive;
    use uv_kernel2::note::Note;
    use uv_wallet2::accept::Lineage;
    use uv_wallet2::store::Held;

    let tip = chain.tip().map_err(|e| {
        crate::Error::ChainUnavailable(format!(
            "cannot stamp the issuance floor: {e}\nnothing was written; retry when the node answers"
        ))
    })?;
    let issued_below = Some(tip.saturating_sub(REORG_MARGIN));

    let index = wallet.store.allocate_index();
    let keys = derive(&wallet.seed, index);
    let asset = keys.asset_id;
    let note = Note::build(asset, Amount(amount), &keys);
    let commitment = note.commitment();
    wallet
        .store
        .insert(Held {
            note,
            key_index: index,
            lineage: Lineage::new(),
            state: NoteState::Unspent,
        })
        .map_err(|e| crate::Error::Storage(format!("fresh index refused: {e:?}")))?;

    Ok(PreparedIssue {
        issuance: uv_kernel2::issuance::Issuance {
            amount,
            asset,
            commitment,
        },
        anchor: crate::anchor::Anchor {
            asset_hex: hex::encode(digest::encode(&asset)),
            commitment_hex: hex::encode(digest::encode(&commitment)),
            issued_below,
            genesis: crate::anchor::GenesisOpening {
                amount,
                nullifier_anchor_hex: hex::encode(digest::encode(&keys.anchor)),
                randomness_hex: hex::encode(digest::encode(&keys.randomness)),
            },
        },
    })
}

/// Publish the staged issuance, then write the anchor — in that order.
///
/// The record goes to Bitcoin *after* the wallet is durable and *before* the
/// anchor is written: an anchor naming an issuance that never reached the
/// chain would be refused by every receiver, so the anchor is the last thing
/// to appear. Until the record existed, supply was whatever the issuer said —
/// `formal/issuance.qnt` finds the secret-inflation attack in two steps
/// without it.
pub fn publish_issue(
    chain: &mut (impl uv_wallet2::chain::Chain + ?Sized),
    home: &std::path::Path,
    prepared: PreparedIssue,
) -> crate::Result<Issued> {
    chain.publish_issuance(&prepared.issuance).map_err(|e| {
        crate::Error::ChainUnavailable(format!(
            "could not publish the issuance record: {e}\nthe note exists locally but NO \
             receiver will accept it — a lineage whose genesis is not on chain is refused. \
             Re-run `issue` when the node is back, or use a fresh home."
        ))
    })?;
    crate::anchor::write(home, &prepared.anchor)?;
    Ok(Issued {
        amount: prepared.issuance.amount,
        asset_hex: prepared.anchor.asset_hex,
        commitment_hex: prepared.anchor.commitment_hex,
    })
}

/// One inbox file's fate during a scan. The caller renders these; every rule
/// that decides them lives here.
#[derive(Debug)]
pub enum ScanEvent {
    /// Larger than any real payment could be — skipped before reading, so a
    /// stranger's file cannot pull itself into memory to be objected to.
    SkippedOversize { file: String, bytes: u64 },
    /// Verified, settled, and stored. The file is deleted by
    /// [`ScanOutcome::finish`], after the caller persists the wallet.
    Accepted { amount: u64, hops: usize },
    /// Two payers used one address slot. The payment is real and settled on
    /// Bitcoin; it simply has nowhere to sit. Set aside — never discarded —
    /// because this file is the only copy of the lineage; a fresh address
    /// makes it collectable. `peer` names the batch that reached two payers,
    /// when the ledger can say.
    SlotCollision {
        amount: u64,
        slot: u64,
        peer: Option<String>,
        set_aside: bool,
        aside_dir: std::path::PathBuf,
    },
    /// The store refused for a reason other than a slot collision. Kept.
    StoreRefused { amount: u64, why: String },
    /// Can never become valid. Discarded — junk left in place would cost a
    /// proof verification per hop on every future scan, indefinitely.
    RejectedPermanent { amount: u64, why: String },
    /// Merely early (a record not deep enough, a view mid-resync). Kept:
    /// discarding on a transient verdict is the `ViewIncomplete` bug, and
    /// `formal/delivery.qnt` holds the door on it.
    RejectedTransient { amount: u64, why: String },
}

/// A finished pass over the inbox, with the one dangerous step still pending.
///
/// **Call [`finish`](Self::finish) only after persisting the wallet.** The
/// accepted notes are in the store but only in memory; the files that produced
/// them are still on disk, so a crash before the save costs a rescan and
/// nothing else. Deleting first inverts that: any early exit destroys money
/// that was never written down — measured once at a wallet owed 700 ending
/// with 300, which is why the type will not let the deletes happen by
/// accident.
#[must_use = "accepted notes are only in memory; persist the wallet, then call finish() to delete their files"]
pub struct ScanOutcome {
    pub events: Vec<ScanEvent>,
    pub accepted: usize,
    pub rejected: usize,
    accepted_files: Vec<std::path::PathBuf>,
}

impl ScanOutcome {
    /// Delete the files whose notes are now durable. Durable first,
    /// irreversible second — the caller's save goes before this call.
    pub fn finish(self) {
        for p in self.accepted_files {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// A bundle is one sealed envelope per hop of lineage, and `MAX_LINEAGE` caps
/// the hops, so anything past this ceiling is not a payment.
const MAX_BUNDLE_BYTES: u64 = (uv_wallet2::accept::MAX_LINEAGE as u64 + 2) * 256 * 1024;

/// Process everything in the inbox against this wallet: open what is ours,
/// validate whole lineages, store what settles, and classify the rest —
/// keep-on-transient, discard-on-permanent, set-aside-on-collision.
///
/// Fetching mail is the caller's job (carriers differ between a terminal and
/// a phone); from the directory down, nothing knows how a file arrived.
pub fn scan_inbox(
    home: &std::path::Path,
    wallet_name: &str,
    wallet: &mut Wallet,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
    anchor: &crate::anchor::Anchor,
) -> crate::Result<ScanOutcome> {
    use uv_kernel2::amount::Amount;
    use uv_kernel2::keys::derive;
    use uv_kernel2::note::Note;
    use uv_wallet2::accept::{accept, TrustAnchor};
    use uv_wallet2::store::{Held, StoreError};

    // **Refresh before judging anything.** The genesis gate asks the chain for
    // its issuance records, and a cold index has none — so a first scan against
    // a freshly-built view reported `GenesisNotIssued` for perfectly good mail
    // and kept it for a later run. Fails closed, so no money was at risk, but a
    // wallet that answers "your issuance is not on chain" about an issuance
    // that is on chain is confidently wrong, which is the failure mode `supply`
    // already refreshes to avoid. Found by the front-running demo on a cold index.
    chain.refresh();

    let bad = |field: &str| {
        crate::Error::BadInput(format!("anchor.json: {field} is not a canonical digest"))
    };
    let asset = decode_digest(&anchor.asset_hex).ok_or_else(|| bad("asset_hex"))?;
    let anchor_commitment =
        decode_digest(&anchor.commitment_hex).ok_or_else(|| bad("commitment_hex"))?;
    let (scan_secret, _) = uv_envelope::derive_scan(&wallet.seed.0);
    let cfg = uv_air::prove::hiding_config();
    let batches = crate::batches::read(home, wallet_name);

    let mut events = Vec::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut accepted_files = Vec::new();

    let dir = crate::home::inbox_dir(home);
    let entries = std::fs::read_dir(&dir).into_iter().flatten().flatten();
    for e in entries {
        match e.metadata() {
            Ok(m) if m.len() > MAX_BUNDLE_BYTES => {
                events.push(ScanEvent::SkippedOversize {
                    file: e.file_name().to_string_lossy().into_owned(),
                    bytes: m.len(),
                });
                continue;
            }
            Ok(_) => {}
            Err(_) => continue,
        }
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        // Trial-decapsulation: an envelope that will not open was not for us.
        // There is no identifier to match on, by design — an identifier is
        // exactly the metadata this is meant not to leak.
        let Ok(sealed) = bincode::deserialize::<uv_envelope::Sealed>(&bytes) else {
            continue;
        };
        let Ok(plain) = uv_envelope::open(&scan_secret, &sealed) else {
            continue;
        };
        let Ok(bundle) = bincode::deserialize::<crate::bundle::Bundle>(&plain) else {
            continue;
        };
        // Reconstruct the note from our own derivation — the sender never
        // sends us secrets, only which request they paid.
        let keys = derive(&wallet.seed, bundle.index);
        let note = Note::build(asset, Amount(bundle.amount), &keys);
        if wallet.store.get(&note.commitment()).is_some() {
            continue; // already ingested
        }
        match accept(
            &cfg,
            chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &anchor_commitment,
                issued_below: anchor.issued_below,
                genesis_amount: anchor.genesis.amount,
            },
            &note,
            &bundle.lineage,
        ) {
            Ok(()) => {
                let hops = bundle.lineage.len();
                match wallet.store.insert(Held {
                    note,
                    key_index: bundle.index,
                    lineage: bundle.lineage,
                    state: NoteState::Unspent,
                }) {
                    Ok(()) => {
                        events.push(ScanEvent::Accepted {
                            amount: bundle.amount,
                            hops,
                        });
                        accepted += 1;
                        accepted_files.push(e.path());
                    }
                    // **Never a panic.** `key_index` comes off the wire from
                    // whoever paid, and two payers holding one address both
                    // start at slot zero without either doing anything wrong.
                    // The payment is real; what is missing is a free slot.
                    Err(StoreError::IndexReused(i)) => {
                        let aside = crate::home::unplaceable_dir(home);
                        let set_aside = std::fs::create_dir_all(&aside).is_ok()
                            && e.file_name()
                                .to_str()
                                .map(|n| std::fs::rename(e.path(), aside.join(n)).is_ok())
                                .unwrap_or(false);
                        events.push(ScanEvent::SlotCollision {
                            amount: bundle.amount,
                            slot: i,
                            peer: crate::batches::batch_of(&batches, i)
                                .and_then(|b| b.peer.clone()),
                            set_aside,
                            aside_dir: aside,
                        });
                        rejected += 1;
                    }
                    Err(other) => {
                        events.push(ScanEvent::StoreRefused {
                            amount: bundle.amount,
                            why: format!("{other:?}"),
                        });
                        rejected += 1;
                    }
                }
            }
            Err(why) => {
                if why.is_permanent() {
                    let _ = std::fs::remove_file(e.path());
                    events.push(ScanEvent::RejectedPermanent {
                        amount: bundle.amount,
                        why: format!("{why:?}"),
                    });
                } else {
                    events.push(ScanEvent::RejectedTransient {
                        amount: bundle.amount,
                        why: format!("{why:?}"),
                    });
                }
                rejected += 1;
            }
        }
    }

    Ok(ScanOutcome {
        events,
        accepted,
        rejected,
        accepted_files,
    })
}

/// A payment, planned and gated, with the payee's slots already reserved.
///
/// Everything that can refuse has refused by the time this exists — before a
/// single record reaches Bitcoin, and before anything was reserved. A payment
/// that publishes two of its three records and then hits an exhausted address
/// has spent real money and paid nobody in full; a reservation written after
/// a crash-prone step is a slot that gets reused, and two notes under one
/// slot share a one-time anchor. Hence the order this constructor enforces:
/// select once, partition replays out, gate everything, reserve last.
#[must_use = "slots are reserved for this plan; execute it or the reservation is a burnt batch"]
pub struct SendPlan {
    /// Notes whose key already signed: rebroadcasts, not payments. They need
    /// no slot and mail nothing — the replayed payload pays whoever the
    /// original paid.
    pub replays: Vec<uv_air::poseidon2::Digest>,
    /// Fresh parts: which note funds it, how much, and the payee slot it pays.
    pub fresh: Vec<(uv_air::poseidon2::Digest, u64, crate::address::Slot)>,
    /// The whole plan as selected, in order — for the caller's narration.
    pub parts: Vec<u64>,
}

/// Plan a payment of `amount` to `address`, reserving the slots it needs.
///
/// Selection happens once, against the store as it is now — never per part,
/// where iteration two could pick the change note iteration one just created,
/// whose lineage ends in a one-block-deep hop the payee would bounce.
/// `from` pins the input note instead (a single-note payment of exactly
/// `amount` from that note).
pub fn plan_send(
    home: &std::path::Path,
    wallet: &Wallet,
    address: &crate::address::Address,
    amount: u64,
    from: Option<&uv_air::poseidon2::Digest>,
) -> crate::Result<SendPlan> {
    use uv_kernel2::amount::Amount;

    let anchor = crate::anchor::read(home)?
        .ok_or_else(|| crate::Error::NotFound("no anchor.json — nothing to pay with".into()))?;
    let asset = decode_digest(&anchor.asset_hex).ok_or_else(|| {
        crate::Error::BadInput("anchor.json: asset_hex is not a canonical digest".into())
    })?;

    // Which notes fund this. A transfer takes exactly one input, so a payment
    // larger than any single note becomes several payments that add up
    // (spec/99 `[MERGE]`).
    let plan: Vec<(uv_air::poseidon2::Digest, Amount)> = match from {
        Some(c) => vec![(*c, Amount(amount))],
        None => {
            uv_wallet2::store::select(&wallet.store, &asset, Amount(amount)).ok_or_else(|| {
                let have: u64 = wallet
                    .store
                    .iter()
                    .filter(|h| h.state == NoteState::Unspent && h.note.asset == asset)
                    .map(|h| h.note.amount.0)
                    .sum();
                let other: u64 = wallet
                    .store
                    .iter()
                    .filter(|h| h.state == NoteState::Unspent && h.note.asset != asset)
                    .map(|h| h.note.amount.0)
                    .sum();
                // Worth saying: a wallet can look full and still be unable to
                // pay, because notes of another asset cannot fund this one.
                let mut msg =
                    format!("spendable balance is {have} for this asset, cannot pay {amount}");
                if other > 0 {
                    msg.push_str(&format!(
                        "\n({other} held in notes of a different asset, which cannot fund this)"
                    ));
                }
                crate::Error::Refused(msg)
            })?
        }
    };

    // A note whose key already signed is a *rebroadcast*, not a new payment.
    // Sorting that out here, before any reservation, is what stops a replay
    // burning a fresh slot on a bundle the payee is guaranteed to refuse.
    let replays: Vec<uv_air::poseidon2::Digest> = plan
        .iter()
        .filter(|(c, _)| {
            wallet
                .store
                .get(c)
                .is_some_and(|h| wallet.log.get(h.key_index).is_some())
        })
        .map(|(c, _)| *c)
        .collect();
    let fresh_parts: Vec<(uv_air::poseidon2::Digest, Amount)> = plan
        .iter()
        .filter(|(c, _)| !replays.contains(c))
        .cloned()
        .collect();

    // Everything that can refuse, refuses now.
    let addr_id = crate::slots::address_id(&address.scan.x25519_hex, &address.scan.ml_kem_hex);
    let mut used = crate::slots::read(home, &addr_id)?;
    let free: Vec<&crate::address::Slot> = address
        .slots
        .iter()
        .filter(|s| !used.contains(&s.index))
        .collect();
    if free.len() < fresh_parts.len() {
        let (n, f) = (fresh_parts.len(), free.len());
        return Err(crate::Error::Refused(if f == 0 {
            "address exhausted: every slot is spent, ask for a fresh batch".into()
        } else {
            let s_note = if n == 1 { "" } else { "s" };
            let s_slot = if f == 1 { "" } else { "s" };
            format!(
                "this payment needs {n} note{s_note} and the address has {f} slot{s_slot} \
                 left — ask for a fresh batch"
            )
        }));
    }

    // Validate every slot before reserving any: a malformed hex field used to
    // panic *after* the reservation write, so one bad slot in a multi-note
    // plan burnt every slot in it.
    let slots: Vec<crate::address::Slot> =
        free.into_iter().take(fresh_parts.len()).cloned().collect();
    for sl in &slots {
        for (what, hexs) in [
            ("nullifier_anchor", &sl.nullifier_anchor_hex),
            ("randomness", &sl.randomness_hex),
        ] {
            if decode_digest(hexs).is_none() {
                return Err(crate::Error::BadInput(format!(
                    "address slot {}: {what} is not a valid digest\nrefusing before \
                     reserving anything",
                    sl.index
                )));
            }
        }
    }
    // And the scan key — probed with a real seal of an empty payload rather
    // than re-implementing the hex/length rules: validation by the exact
    // function later trusted cannot drift from it. Found the hard way: sealing
    // used to fail *after* the record was on Bitcoin.
    if !fresh_parts.is_empty() && uv_envelope::seal(&address.scan, &[]).is_err() {
        return Err(crate::Error::BadInput(
            "address scan key is malformed: bundles could never be sealed to this \
             payee\nrefusing before reserving anything"
                .into(),
        ));
    }

    // Reserve *before* publishing anything. Reservations used to be written
    // after the mailing, so a crash mid-payment lost them, a retry reused
    // slot 0, and two notes on one slot share a one-time anchor. Reserving
    // first costs, at worst, a slot burnt by a payment that never happened.
    if !slots.is_empty() {
        let newly: Vec<u64> = slots.iter().map(|s| s.index).collect();
        crate::slots::reserve(home, &addr_id, &mut used, &newly)?;
    }

    Ok(SendPlan {
        replays,
        fresh: fresh_parts
            .iter()
            .zip(slots)
            .map(|(&(c, a), s)| (c, a.0, s))
            .collect(),
        parts: plan.iter().map(|(_, a)| a.0).collect(),
    })
}

/// Build, serialize, and seal one part's bundle to the payee. Returns the
/// wire name (the nullifier, so payer and payee agree on identity) and the
/// sealed bytes for whatever carrier the caller uses.
///
/// bincode, not JSON: the bundle is mostly proof bytes, and JSON encodes a
/// byte array as decimal numbers — ~4x bloat on the protocol's worst scaling
/// axis (one proof per hop of history).
pub fn seal_bundle(
    scan: &uv_envelope::ScanPublic,
    slot_index: u64,
    amount: u64,
    asset_hex: &str,
    lineage: uv_wallet2::accept::Lineage,
    nullifier: &uv_air::poseidon2::Digest,
) -> crate::Result<(String, Vec<u8>)> {
    let bundle = crate::bundle::Bundle {
        index: slot_index,
        amount,
        asset_hex: asset_hex.to_string(),
        lineage,
    };
    let plain = bincode::serialize(&bundle)
        .map_err(|e| crate::Error::Storage(format!("serialize bundle: {e}")))?;
    let sealed = uv_envelope::seal(scan, &plain).map_err(|e| {
        crate::Error::BadInput(format!("could not seal the bundle to the payee: {e:?}"))
    })?;
    let wire = bincode::serialize(&sealed)
        .map_err(|e| crate::Error::Storage(format!("serialize sealed: {e}")))?;
    let name = format!("{}.uvb", hex::encode(digest::encode(nullifier)));
    Ok((name, wire))
}

/// Generate `count` fresh payment slots and record the batch.
///
/// The batch is recorded **before** the address is handed out, so the ledger
/// can never claim fewer slots are outstanding than really are. `peer` is a
/// free-text label — nothing authenticates it — kept so a later slot collision
/// can name the counterparty whose batch reached two payers.
///
/// One batch goes to ONE counterparty: giving the same batch to two payers
/// means both start at slot 0, and the second payment has nowhere to sit
/// (`ScanEvent::SlotCollision`).
pub fn make_address(
    home: &std::path::Path,
    wallet_name: &str,
    wallet: &mut Wallet,
    count: u64,
    peer: Option<&str>,
) -> crate::Result<crate::address::Address> {
    use uv_kernel2::keys::derive;

    let slots: Vec<crate::address::Slot> = (0..count)
        .map(|_| {
            let index = wallet.store.allocate_index();
            let keys = derive(&wallet.seed, index);
            crate::address::Slot {
                index,
                nullifier_anchor_hex: hex::encode(digest::encode(&keys.anchor)),
                randomness_hex: hex::encode(digest::encode(&keys.randomness)),
            }
        })
        .collect();

    if let Some(first) = slots.first().map(|s| s.index) {
        crate::batches::append(
            home,
            wallet_name,
            crate::batches::Batch {
                peer: peer.map(str::to_string),
                first,
                count,
            },
        )?;
    }

    let (_, scan) = uv_envelope::derive_scan(&wallet.seed.0);
    Ok(crate::address::Address { scan, slots })
}

/// Hex → canonical digest, refusing non-canonical limbs. The fallible form
/// only: a panic on a counterparty's file is a denial of service they mailed
/// in.
/// One delivered part of a payment: a sealed bundle the caller must carry.
///
/// `send` deliberately does not deliver. The CLI mailed through a `Transport`,
/// the Signal fork hands these to the chat layer as attachments, and a test
/// writes them straight into the payee's inbox. Delivery is the one thing that
/// differs between callers, so it is the one thing not here.
pub struct SentPart {
    /// The bundle's filename on whatever carrier moves it.
    pub bundle_name: String,
    /// The sealed wire bytes — ciphertext end to end.
    pub bundle_wire: Vec<u8>,
    pub nullifier_hex: String,
    pub amount: u64,
}

/// What a send did, in numbers a caller can render or assert on.
pub struct SendOutcome {
    /// Spends that were already signed and were re-published byte-for-byte.
    /// Nothing was mailed for these and no slot was consumed — they pay
    /// whoever the original payment paid.
    pub rebroadcast: usize,
    /// How the amount split across notes (one entry per fresh part).
    pub parts: Vec<u64>,
    pub sent: Vec<SentPart>,
}

/// Execute a payment: plan, replay what must be replayed, prove and publish
/// the rest, and seal one bundle per fresh part for the caller to deliver.
///
/// **Moved here from the CLI on 2026-07-30, and the move is the point.** The
/// planning half (`plan_send`: selection, replay partitioning, slot and scan-key
/// validation, reserve-before-publish) has lived here since the iOS extraction;
/// the *execution* half — rebroadcast-first, prepare, the persist-before-
/// broadcast ordering, lineage assembly, sealing — stayed in `cli/src/main.rs`,
/// which meant the FFI could not send and the end-to-end flow was only
/// exercisable through a shell script. Every rule below is shared now; what a
/// caller keeps is delivery and words.
///
/// The ordering disciplines, restated because they are the contract:
///
/// - **Replays run first and separately.** They are not this payment; they
///   re-publish bytes an earlier command signed, and consume nothing.
/// - **The wallet is persisted between `prepare` and `broadcast`.** A signature
///   that reaches Bitcoin before it reaches disk is a signature a crashed
///   wallet will make again with a different slot.
/// - **A carrier failure after publish costs delivery, not money** — the record
///   is on the chain; re-running rebroadcasts harmlessly and re-seals.
#[allow(clippy::too_many_arguments)]
pub fn send(
    home: &std::path::Path,
    wallet_name: &str,
    wallet: &mut Wallet,
    chain: &mut (impl uv_wallet2::chain::Chain + ?Sized),
    config: &uv_air::prove::Vouched<uv_air::prove::HidingConfig>,
    address: &crate::address::Address,
    amount: u64,
    from: Option<&uv_air::poseidon2::Digest>,
    passphrase: Option<&str>,
) -> crate::Result<SendOutcome> {
    use uv_kernel2::amount::Amount;
    use uv_wallet2::send::{broadcast, prepare, rebroadcast, Recipient, WalletCtx};

    let plan = plan_send(home, wallet, address, amount, from)?;

    let anchor = crate::anchor::read(home)?
        .ok_or_else(|| crate::Error::NotFound("no anchor.json".into()))?;
    let asset_hex = anchor.asset_hex.clone();

    // Replays first: nothing reserved, nothing mailed, pays the original payee.
    let mut rebroadcast_count = 0usize;
    for input in &plan.replays {
        let key_index = wallet
            .store
            .get(input)
            .ok_or_else(|| crate::Error::Refused("selected note vanished from the store".into()))?
            .key_index;
        rebroadcast(chain, &wallet.log, key_index)
            .map_err(|e| crate::Error::Refused(format!("could not rebroadcast: {e:?}")))?
            .ok_or_else(|| {
                crate::Error::Refused(
                    "partitioned as a replay but the sign-log holds no entry — \
                     the wallet state is inconsistent; do not force"
                        .into(),
                )
            })?;
        rebroadcast_count += 1;
    }

    let mut sent = Vec::with_capacity(plan.fresh.len());
    for (input, part, slot) in &plan.fresh {
        let recipient = Recipient {
            nullifier_anchor: decode_digest(&slot.nullifier_anchor_hex).ok_or_else(|| {
                crate::Error::BadInput("address slot: non-canonical anchor".into())
            })?,
            randomness: decode_digest(&slot.randomness_hex).ok_or_else(|| {
                crate::Error::BadInput("address slot: non-canonical randomness".into())
            })?,
        };

        // Sign and log, but do not broadcast — and if this refuses, persist
        // what has happened so far before returning: earlier parts in this
        // loop are already on Bitcoin.
        let prepared = match prepare(
            config,
            WalletCtx {
                store: &mut wallet.store,
                log: &mut wallet.log,
                seed: &wallet.seed,
            },
            input,
            &recipient,
            Amount(*part),
        ) {
            Ok(p) => p,
            Err(e) => {
                let _ = crate::wallet::save(
                    home,
                    wallet_name,
                    &wallet.seed,
                    &wallet.store,
                    &wallet.log,
                    passphrase,
                );
                return Err(crate::Error::Refused(format!(
                    "send refused after {} of {} parts published: {e:?}",
                    sent.len(),
                    plan.fresh.len()
                )));
            }
        };

        let out = broadcast(chain, prepared, || {
            crate::wallet::save(
                home,
                wallet_name,
                &wallet.seed,
                &wallet.store,
                &wallet.log,
                passphrase,
            )
        })
        .map_err(|e| {
            crate::Error::Refused(format!(
                "could not publish: {e:?} — the spend is signed; re-running \
                 rebroadcasts the identical payload. Do not build a new one."
            ))
        })?;
        debug_assert!(!out.replayed, "replays were partitioned out above");

        let mut lineage = wallet
            .store
            .get(input)
            .map(|h| h.lineage.clone())
            .unwrap_or_default();
        lineage.push(out.hop.clone());

        // The record is on Bitcoin at this point: a failure here costs
        // delivery, never money, and the message says so.
        let (name, wire) = seal_bundle(
            &address.scan,
            slot.index,
            *part,
            &asset_hex,
            lineage,
            &out.transfer.nullifier,
        )
        .map_err(|e| {
            crate::Error::Storage(format!(
                "record PUBLISHED but the bundle was not sealed: {e} — the money \
                 is settled; re-run to rebroadcast harmlessly and re-seal"
            ))
        })?;

        sent.push(SentPart {
            bundle_name: name,
            bundle_wire: wire,
            nullifier_hex: hex::encode(digest::encode(&out.transfer.nullifier)),
            amount: *part,
        });
    }

    crate::wallet::save(
        home,
        wallet_name,
        &wallet.seed,
        &wallet.store,
        &wallet.log,
        passphrase,
    )?;

    Ok(SendOutcome {
        rebroadcast: rebroadcast_count,
        parts: plan.parts,
        sent,
    })
}

/// Reconcile the wallet against the chain: quarantine what a reorg orphaned,
/// restore what settled again.
///
/// The genesis half comes from the home's anchor, when there is one. An
/// unreadable anchor runs the pass without it rather than refusing — a wallet
/// must be able to react to a reorg even when a side file is broken.
pub fn reconcile(
    home: &std::path::Path,
    wallet: &mut Wallet,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
) -> uv_wallet2::reconcile::Reconciled {
    use uv_wallet2::reconcile::{reconcile, Genesis};

    let parts = crate::anchor::read(home).ok().flatten().and_then(|a| {
        Some((
            decode_digest(&a.asset_hex)?,
            decode_digest(&a.commitment_hex)?,
            a.genesis.amount,
        ))
    });
    let genesis = parts.as_ref().map(|(a, c, amt)| Genesis {
        asset: a,
        commitment: c,
        amount: *amt,
    });
    reconcile(chain, &mut wallet.store, &wallet.log, genesis.as_ref())
}

fn decode_digest(s: &str) -> Option<uv_air::poseidon2::Digest> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    digest::decode(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uv_kernel2::amount::Amount;
    use uv_kernel2::keys::{derive, WalletSeed};
    use uv_kernel2::note::Note;
    use uv_wallet2::accept::Lineage;
    use uv_wallet2::signlog::SignLog;
    use uv_wallet2::store::{Held, Store};

    fn wallet_with(states: &[(u64, NoteState)]) -> Wallet {
        let seed = WalletSeed([9u8; 32]);
        let mut store = Store::default();
        for &(amount, state) in states {
            let key_index = store.allocate_index();
            store
                .insert(Held {
                    note: Note::build(
                        [p3_baby_bear::BabyBear::new(0xA5); 8],
                        Amount(amount),
                        &derive(&seed, key_index),
                    ),
                    key_index,
                    lineage: Lineage::new(),
                    state,
                })
                .expect("fresh store");
        }
        Wallet {
            seed,
            store,
            log: SignLog::default(),
        }
    }

    /// The classification that makes a balance honest: only `Unspent` counts.
    /// Exhaustive over every state, so a new `NoteState` variant cannot slip
    /// into the spendable sum by default — the same no-wildcard discipline as
    /// `accept`'s verdicts.
    #[test]
    fn only_unspent_notes_are_spendable() {
        let all = [
            NoteState::Unspent,
            NoteState::InFlight,
            NoteState::Spent,
            NoteState::Quarantined,
        ];
        let b = balance(&wallet_with(&all.map(|s| (100, s))));
        assert_eq!(b.spendable, 100, "exactly the one Unspent note");
        assert_eq!(b.notes.len(), all.len(), "but every note is listed");
        // The match below exists to break this test at compile time if a new
        // state is added — decide then whether it is spendable.
        for line in &b.notes {
            match line.state {
                NoteState::Unspent
                | NoteState::InFlight
                | NoteState::Spent
                | NoteState::Quarantined => {}
            }
        }
    }

    #[test]
    fn an_empty_wallet_has_zero_and_no_lines() {
        let b = balance(&wallet_with(&[]));
        assert_eq!(b.spendable, 0);
        assert!(b.notes.is_empty());
    }
}
