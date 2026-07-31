//! The receive path: validate a note's entire lineage, then trust it.
//!
//! Every check here exists because a formal model produced a counterexample
//! without it:
//!
//! - **Per-hop proofs** (`verify_hiding`): the STARK says each transition was
//!   well-formed, conserving, and authorized. It says nothing about ancestors.
//! - **Linkage** (`formal/linkage.qnt`, `checked`): each hop must consume an
//!   output of the hop before it. Off-circuit since the rewrite dropped
//!   in-circuit recursion, so the receiver runs it — a hop consuming a note
//!   nobody created is exactly the `fabricateHop` attack.
//! - **History binding** (`formal/multihop.qnt`, `bound`): each hop's
//!   `prev_history` must equal the fold of the bundle hashes before it. The
//!   digest is inside the signed bundle hash, so a lineage cannot be spliced
//!   or truncated without every later signature dying.
//! - **Settlement, whole ancestry** (`formal/multihop.qnt`): every hop's
//!   nullifier must have won its first-occurrence race, at depth. Checking
//!   only your own hop is the inflation bug.
//!
//! The genesis anchor: hop 0 must spend a commitment the receiver already
//! trusts as the asset's issuance (passed in, not taken from the sender) and
//! start from the empty history. Issuance policy — who may mint, how the
//! anchor is published, and whether anyone can check the supply — is spec/99
//! `[SUPPLY]`; this module takes the anchor as given.
//!
//! Worth being exact about what that means: the origin check here is **byte
//! equality** against a commitment the caller was handed out of band. It does
//! not verify that any key authorised the issuance, what amount the commitment
//! opens to, or that only one genesis exists for the asset. A receiver's
//! strongest statement is "my note descends from the commitment I was given,
//! and no more value than that commitment holds exists under it" — which says
//! nothing about how many such commitments the issuer made.

use bincode::Options as _;
use uv_air::poseidon2::Digest;
use uv_air::prove::{HidingConfig, Vouched};
use uv_kernel2::history;
use uv_kernel2::note::Note;
use uv_kernel2::transfer::Transfer;
use uv_kernel2::transfer_prove::{verify_hiding, RefusedHiding};

use crate::chain::{required_confirmations, Chain, Lookup, Occurrence};

/// One hop as it travels: the public transfer and its hiding proof. There is no
/// `owner_pk` — the note carries none (spec/99 `[PROOF-AUTH]`), so the transfer
/// alone determines the statement the proof is bound to.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub transfer: Transfer,
    /// Serialized `HidingAuthProtoProof`.
    pub proof: Vec<u8>,
}

/// A note's full ancestry, oldest hop first.
pub type Lineage = Vec<Hop>;

/// Why a note was refused. Mirrors the v1 wallet's `Rejected`, extended with
/// the proof layer.
#[derive(Debug)]
pub enum Rejected {
    /// The lineage is empty — nothing connects the note to an issuance.
    NoLineage,
    /// Hop 0 does not spend the trusted genesis commitment, or does not start
    /// from the empty history.
    WrongGenesis,
    /// A proof failed to deserialize or verify.
    BadProof(usize),
    /// Hop `i` does not consume an output of hop `i-1` (`fabricateHop`).
    NotLinked(usize),
    /// Hop `i`'s claimed prev_history is not the fold of what came before —
    /// a spliced or truncated ancestry.
    NotThisNotesAncestry(usize),
    /// Hop `i`'s nullifier has no confirmed record.
    NoRecord(usize),
    /// Hop `i`'s record exists but binds a different bundle — the hop lost
    /// its first-occurrence race, and everything after it is void.
    LostRace(usize),
    /// Hop `i` settled but is not yet deep enough for this value.
    InsufficientDepth(usize),
    /// The note being received is not an output of the final hop.
    NotAnOutput,
    /// The chain view cannot see far enough back to answer for hop `i`.
    ///
    /// Not a verdict about the payment — a verdict about *us*. The view may
    /// widen (a resync finishes, a floor is lowered), so this is transient and
    /// the bundle is kept.
    ViewIncomplete(usize),
    /// The genesis this lineage claims has no confirmed issuance record.
    ///
    /// Transient: the issuance may simply not be deep enough yet, or this
    /// view may not have caught up. It is never a reason to destroy the
    /// bundle.
    GenesisNotIssued,
    /// This view holds issuance records, but none commits to *this* genesis.
    ///
    /// Carries how many it did see, which is the difference between "nothing
    /// has confirmed" and "the chain is issuing, just not this".
    GenesisNotOnChain { records_seen: usize },
    /// The lineage is longer than any real coin's history plausibly is.
    ///
    /// A receiver verifies *every* hop, so an unbounded lineage is unbounded
    /// attacker-chosen work. See [`MAX_LINEAGE`].
    TooLong(usize),
}

impl Rejected {
    /// **May the caller destroy the bundle?** `true` means yes.
    ///
    /// The name says "permanent" and for every variant but one that is the same
    /// question as "will this ever verify?". It is not the same question, and
    /// `TooLong` is where they part company — see below. The only consumer is
    /// `scan_inbox`, which deletes the file when this returns `true`, and a
    /// bundle is the only copy of its lineage.
    ///
    /// The distinction is what lets a receiver throw junk away. A structurally
    /// broken or losing lineage is dead forever and re-checking it is pure
    /// waste. A hop that has not settled yet, or has not settled *deeply*
    /// enough, is a payment in flight and must be kept.
    ///
    /// Note that reaching either transient verdict already costs the sender a
    /// lineage that verifies all the way back to a trusted issuance, which junk
    /// by definition does not have. So this is not a hole an attacker can aim
    /// at: to get their mail retained they must first send something real.
    /// **Exhaustive on purpose — no wildcard.** This was
    /// `!matches!(self, NoRecord | InsufficientDepth)`, which meant every
    /// variant not named there defaulted to *permanent*, and permanent means
    /// the caller deletes the bundle. A default of "destroy the only copy of
    /// someone's lineage" is the wrong way round, and it had already caught
    /// one variant: `ViewIncomplete`, whose own doc comment says it is
    /// transient and the bundle is kept.
    ///
    /// Written as a full match so adding a variant is a compile error rather
    /// than a silent classification.
    pub fn is_permanent(&self) -> bool {
        match self {
            // Transient: the payment may yet become acceptable.
            Rejected::NoRecord(_) | Rejected::InsufficientDepth(_) => false,
            // Transient: an issuance record that has not confirmed yet, or a
            // view that has not caught up, is not a verdict about the money.
            Rejected::GenesisNotIssued => false,
            // **Transient, and it is worth saying why**, because the reflex is
            // to call it permanent: this fires both when the anchor is lying
            // and when the issuer's record is simply one block behind other
            // people's. Nothing here distinguishes them — a record that has
            // not confirmed yet and a record that never will look identical
            // from a chain view. So the classification follows the cost, and
            // the two costs are not symmetric: transient-when-permanent leaves
            // junk on disk, permanent-when-transient destroys a bundle whose
            // issuance confirms in the next block. The same asymmetry that
            // `ViewIncomplete` below got wrong.
            Rejected::GenesisNotOnChain { .. } => false,
            // Transient, and the one that was wrong. A view too narrow to
            // answer says nothing about the payment — it says something about
            // *us*, and a resync or a lowered floor fixes it. Discarding here
            // means a node that was mid-catch-up costs its owner real money.
            // It is also what an attacker gets for free by wedging a
            // non-canonical record against a nullifier (spec/99 `[FRONTRUN]`):
            // the payee destroys their own bundle.
            Rejected::ViewIncomplete(_) => false,
            // Permanent: no future state of the chain or of our view makes
            // any of these valid.
            // Transient, and it is the one entry here that will never verify.
            //
            // A lineage does not get shorter, so `TooLong` is permanent in the
            // sense the name suggests — and it is classified transient anyway,
            // deliberately. **The question this function actually decides is
            // "may I destroy the only copy?", not "will this ever verify?"**,
            // because its sole consumer is `scan_inbox`'s `remove_file`. Those
            // two questions have the same answer for every other variant and
            // opposite answers for this one.
            //
            // Deleting here costs someone a lineage that a longer `MAX_LINEAGE`,
            // a repaired sender, or the accumulator (spec/99 `[ACC]`) could still
            // make spendable. Keeping it costs disk. The DoS defence that
            // `MAX_LINEAGE` exists for is the *refusal*, which bounds verification
            // work and still happens; deletion was never what bounded it.
            Rejected::TooLong(_) => false,
            Rejected::NoLineage
            | Rejected::WrongGenesis
            | Rejected::BadProof(_)
            | Rejected::NotLinked(_)
            | Rejected::NotThisNotesAncestry(_)
            | Rejected::LostRace(_)
            | Rejected::NotAnOutput => true,
        }
    }
}

/// The longest lineage a receiver will look at.
///
/// Every hop costs a proof verification and ~208 KB on the wire, and the count
/// is chosen by whoever sends you the note. A coin that has passed through 256
/// hands is already extraordinary; anything near this is pathological rather
/// than unlucky. The real answer is the accumulator (spec/99 `[ACC]`), which
/// removes per-hop ancestry altogether — this is a bound, not a design.
pub const MAX_LINEAGE: usize = 256;

/// What a receiver trusts about an asset's issuance.
///
/// These four travelled as separate parameters and are one thing: they all come
/// from the same `anchor.json`, they are all about the *origin* of a lineage
/// rather than any hop in it, and none of them means anything without the
/// others. Grouping them is not tidiness — a caller passing `genesis_amount`
/// from one anchor and `genesis_commitment` from another would be checking a
/// lineage against two different issuances, and the type now makes that
/// awkward to write by accident.
pub struct TrustAnchor<'a> {
    pub asset: &'a Digest,
    /// The commitment hop 0 must spend. Byte equality against a value handed
    /// over out of band — see the module docs for how weak that is on its own.
    pub genesis_commitment: &'a Digest,
    /// The height below which this asset had not been issued, if known. `None`
    /// means an anchor written before issuance heights existed — the floor
    /// cannot be checked and is not.
    pub issued_below: Option<u64>,
    /// The genesis note's amount, from the anchor's opening.
    ///
    /// **Not an `Option`, deliberately.** It was one, so that anchors written
    /// before issuance went on chain could still validate — and an `Option`
    /// there is not a missing value, it is a spelling for "skip the supply
    /// check". Removing it removes the allowance as a *category*: there is now
    /// no way to construct a `TrustAnchor` that disables the rule. Anchors
    /// without an opening are refused at import instead, where a person can
    /// read the reason.
    pub genesis_amount: u64,
}

/// Validate `note` against its `lineage` and the chain, at the receiver's
/// confirmation policy. On `Ok`, the note is safe to hold and re-spend.
pub fn accept(
    config: &Vouched<HidingConfig>,
    chain: &(impl Chain + ?Sized),
    trust: &TrustAnchor<'_>,
    note: &Note,
    lineage: &Lineage,
) -> Result<(), Rejected> {
    let TrustAnchor {
        asset,
        genesis_commitment,
        issued_below,
        genesis_amount,
    } = *trust;
    if lineage.is_empty() {
        return Err(Rejected::NoLineage);
    }
    if lineage.len() > MAX_LINEAGE {
        return Err(Rejected::TooLong(lineage.len()));
    }

    // Can this chain view see the whole of the asset's life? If its floor sits
    // above the issuance, an earlier conflicting record could exist below it
    // and every lookup below would answer "nothing found" — which reads as
    // "nothing exists" and accepts a double-spend.
    //
    // Checked here rather than in the CLI on purpose: the iOS build and the
    // Signal path call `accept` directly, and a safety check that lives in one
    // caller is a safety check the next caller does not have.
    if let Some(floor) = issued_below {
        if chain.scan_floor() > floor {
            return Err(Rejected::ViewIncomplete(0));
        }
    }

    // Genesis anchor: the first hop spends the issuance the receiver trusts,
    // starting from the empty history.
    let first = &lineage[0].transfer;
    if first.input_commitment != *genesis_commitment || first.prev_history != history::GENESIS {
        return Err(Rejected::WrongGenesis);
    }

    // **This genesis's own issuance record must be on Bitcoin.**
    //
    // This is what makes supply countable rather than asserted. Without it an
    // issuer mints in secret and a receiver cannot tell: `formal/issuance.qnt`
    // finds that in two steps. With it, an unpublished issuance is worthless,
    // so the sum of confirmed issuance records bounds every coin anyone will
    // take.
    //
    // Never skipped. This used to be wrapped in `if let Some(amount)`, and an
    // anchor with no opening simply did not have its supply checked — a
    // migration allowance that was also a way to spell "trust me". The type no
    // longer permits it.
    let published = chain.issuances();
    if published.is_empty() {
        return Err(Rejected::GenesisNotIssued);
    }
    // **Three byte comparisons against the chain**, where this used to be one
    // hash match.
    //
    // The first version compared only the *amount*, which an attacker mints
    // against for free: watch an honest issuance of 1000 confirm, build your
    // own asset with a genesis note of 1000, hand out an anchor, and every
    // receiver's check is satisfied by somebody else's record. That was fixed
    // by binding to `H(asset ‖ commitment ‖ amount)`.
    //
    // Now the record carries the asset and the commitment in the clear, so
    // there is nothing to recompute — the chain states what a receiver used to
    // have to derive. The same binding, arrived at more directly, and as a side
    // effect the supply became countable: a hash cannot be enumerated, and
    // these fields can.
    if !published.iter().any(|i| {
        i.asset == *asset && i.commitment == *genesis_commitment && i.amount == genesis_amount
    }) {
        return Err(Rejected::GenesisNotOnChain {
            records_seen: published.len(),
        });
    }

    let required = required_confirmations(note.amount.0);
    let mut folded = history::GENESIS;

    for (i, hop) in lineage.iter().enumerate() {
        // The STARK: this transition was well-formed, conserving, authorized.
        // Strict decode: `bincode`'s free `deserialize` calls
        // `.allow_trailing_bytes()`, so `encode(x) ‖ anything` silently decodes
        // to `x`. That is a free malleability channel — the same proof with any
        // suffix you like.
        //
        // It is harmless *today*, and the reason is worth stating because it is
        // an invariant rather than an accident: **serialized bytes are never an
        // identity here.** Everything consensus depends on is hashed over field
        // elements, and the on-chain record is a fixed-width encoding whose
        // decoder rejects out-of-range limbs rather than reducing them. Nothing
        // hashes, compares, or keys on a proof blob.
        //
        // Closing it anyway, because the accumulator design (spec/99 `[ACC]`)
        // would make record encodings consensus-visible, and the cheapest time
        // to remove a malleability channel is before anything depends on it.
        let proof: uv_air::prove::HidingAuthProtoProof = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .deserialize(&hop.proof)
            .map_err(|_| Rejected::BadProof(i))?;
        match verify_hiding(config, &proof, &hop.transfer, asset) {
            Ok(()) => {}
            Err(RefusedHiding::Shape(_)) | Err(RefusedHiding::Proof(_)) => {
                return Err(Rejected::BadProof(i))
            }
        }

        // Linkage: this hop spends what the previous hop created.
        if i > 0
            && !lineage[i - 1]
                .transfer
                .outputs
                .contains(&hop.transfer.input_commitment)
        {
            return Err(Rejected::NotLinked(i));
        }

        // History binding: the claimed position is the real fold. Because
        // prev_history is inside the signed bundle hash, a mismatch here
        // means the ancestry was spliced, not merely mis-shipped.
        if hop.transfer.prev_history != folded {
            return Err(Rejected::NotThisNotesAncestry(i));
        }
        let bundle = hop.transfer.bundle_hash();
        folded = history::advance(&folded, &bundle);

        // Settlement: this hop's record exists, won its race, and is deep
        // enough. EVERY hop — per-hop checks do not compose.
        match chain.first_occurrence(&hop.transfer.nullifier) {
            Lookup::None => return Err(Rejected::NoRecord(i)),
            // The view cannot see far enough back to rule out an earlier
            // conflicting record. Refusing is the only safe answer: treating
            // this as "no conflict" is how an index that starts too late makes
            // a double-spend look valid.
            Lookup::Unanswerable => return Err(Rejected::ViewIncomplete(i)),
            Lookup::Found(Occurrence { bundle_hash, .. }) if bundle_hash != bundle => {
                return Err(Rejected::LostRace(i))
            }
            Lookup::Found(Occurrence { depth, .. }) => {
                if depth < required {
                    return Err(Rejected::InsufficientDepth(i));
                }
            }
        }
    }

    // Finally: the note in hand is actually what the last hop created.
    if !lineage
        .last()
        .expect("non-empty")
        .transfer
        .outputs
        .contains(&note.commitment())
    {
        return Err(Rejected::NotAnOutput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the classification is that a receiver can throw junk
    /// away without throwing away a payment that is merely early. Getting this
    /// backwards in either direction is a bug with real consequences: discard a
    /// transient verdict and you lose someone's money; keep a permanent one and
    /// you re-verify it forever.
    #[test]
    fn only_settlement_verdicts_are_worth_retrying() {
        for transient in [
            Rejected::NoRecord(0),
            Rejected::InsufficientDepth(3),
            // Was in neither list, and classified permanent by the old
            // wildcard — so a node mid-resync deleted real payments, and a
            // wedged nullifier made the payee destroy their own bundle.
            Rejected::ViewIncomplete(0),
            // The supply rule's two. Neither is a verdict about the money:
            // an issuance record that has not confirmed yet, and a view that
            // holds other people's records but not this genesis's, both
            // resolve on their own the moment the record lands.
            Rejected::GenesisNotIssued,
            Rejected::GenesisNotOnChain { records_seen: 3 },
            // Moved here 2026-07-30, and it is the interesting entry: a lineage
            // never gets shorter, so this one really will never verify. It is
            // kept anyway, because this function decides *deletion* and the
            // bundle is the only copy of the lineage. See `is_permanent`.
            Rejected::TooLong(9_999),
        ] {
            assert!(
                !transient.is_permanent(),
                "{transient:?} must not be destroyed"
            );
        }
        for permanent in [
            Rejected::NoLineage,
            Rejected::WrongGenesis,
            Rejected::BadProof(0),
            Rejected::NotLinked(1),
            Rejected::NotThisNotesAncestry(1),
            Rejected::LostRace(0),
            Rejected::NotAnOutput,
        ] {
            assert!(
                permanent.is_permanent(),
                "{permanent:?} can never become valid — it must be discarded"
            );
        }
    }

    /// The tripwire for the test above.
    ///
    /// **This match has no wildcard, so adding a variant to [`Rejected`] stops
    /// the crate compiling until someone comes here** — and the only useful
    /// thing to do here is to also put it in one of the two lists.
    ///
    /// Worth explaining why this exists, because the test above already looks
    /// like it covers everything. It was written *because* `ViewIncomplete`
    /// slipped through an `is_permanent` wildcard and cost real money. Then it
    /// acquired the identical weakness: it is a hand-written list, the supply
    /// rule added two variants, and neither appeared in it. Nobody noticed,
    /// because a list that is missing an entry passes exactly as loudly as a
    /// list that is complete. A test whose coverage is maintained by memory is
    /// not a test of coverage.
    ///
    /// It is a tripwire and not a proof: nothing here forces the new variant
    /// into the right list, only that a human is stopped and made to look.
    /// That is the strongest thing available without a derive macro, and
    /// saying so is better than implying the lists are self-maintaining.
    #[test]
    fn every_verdict_is_classified_somewhere() {
        fn _no_wildcard(r: &Rejected) {
            match r {
                Rejected::NoRecord(_)
                | Rejected::InsufficientDepth(_)
                | Rejected::ViewIncomplete(_)
                | Rejected::GenesisNotIssued
                | Rejected::TooLong(_)
                | Rejected::GenesisNotOnChain { .. } => { /* transient list */ }
                Rejected::NoLineage
                | Rejected::WrongGenesis
                | Rejected::BadProof(_)
                | Rejected::NotLinked(_)
                | Rejected::NotThisNotesAncestry(_)
                | Rejected::LostRace(_)
                | Rejected::NotAnOutput => { /* permanent list */ }
            }
        }
        _no_wildcard(&Rejected::NoLineage);
    }

    /// A chain view that starts above an asset's issuance cannot rule out an
    /// earlier conflicting record. "I found nothing" from such a view is not
    /// the same statement as "nothing exists", and treating it as such is how
    /// a too-high scan floor makes a double-spend look valid.
    #[test]
    fn a_chain_view_that_starts_too_late_is_refused() {
        struct Narrow(u64);
        impl crate::chain::Chain for Narrow {
            fn first_occurrence(&self, _: &Digest) -> crate::chain::Lookup {
                panic!("the floor check must refuse before any lookup happens")
            }
            fn tip(&self) -> Result<u64, crate::chain::ChainViewError> {
                Ok(10_000)
            }
            fn publish_issuance(
                &mut self,
                _: &uv_kernel2::issuance::Issuance,
            ) -> Result<(), crate::chain::PublishError> {
                Ok(())
            }
            fn issuances(&self) -> Vec<uv_kernel2::issuance::Issuance> {
                Vec::new()
            }
            fn publish(
                &mut self,
                _: &uv_kernel2::record::Record,
            ) -> Result<(), crate::chain::PublishError> {
                Ok(())
            }
            fn rollback_epoch(&self) -> u64 {
                0
            }
            fn refresh(&self) {}
            fn scan_floor(&self) -> u64 {
                self.0
            }
        }

        let asset = [p3_baby_bear::BabyBear::default(); 8];
        let note = uv_kernel2::note::Note::build(
            asset,
            uv_kernel2::amount::Amount(1),
            &uv_kernel2::keys::derive(&uv_kernel2::keys::WalletSeed([0u8; 32]), 0),
        );
        let hop = Hop {
            transfer: uv_kernel2::transfer::Transfer {
                input_commitment: asset,
                nullifier: asset,
                outputs: vec![],
                prev_history: history::GENESIS,
            },
            proof: Vec::new(),
        };
        let cfg = uv_air::prove::hiding_config();

        // Floor 500, asset issued below 400: the view cannot see 400..500.
        assert!(matches!(
            accept(
                &cfg,
                &Narrow(500),
                &TrustAnchor {
                    asset: &asset,
                    genesis_commitment: &asset,
                    issued_below: Some(400),
                    // Any value: the floor check refuses before the genesis
                    // check runs, which is the ordering this test relies on.
                    genesis_amount: 1,
                },
                &note,
                &vec![hop.clone()],
            ),
            Err(Rejected::ViewIncomplete(_))
        ));
        // Floor 300, same asset: the view reaches below the issuance, so the
        // floor is not what stops this one.
        assert!(!matches!(
            accept(
                &cfg,
                &Narrow(300),
                &TrustAnchor {
                    asset: &asset,
                    genesis_commitment: &asset,
                    issued_below: Some(400),
                    // Any value: the floor check refuses before the genesis
                    // check runs, which is the ordering this test relies on.
                    genesis_amount: 1,
                },
                &note,
                &vec![hop],
            ),
            Err(Rejected::ViewIncomplete(_))
        ));
    }

    /// Build a trivial one-hop setup: a note, its genesis hop, and a config.
    /// Every supply test below refuses *before* any proof work, so an empty
    /// proof is honest here — if one ever reached verification it would fail
    /// loudly rather than pass by accident.
    ///
    /// **The asset and the genesis commitment are deliberately different
    /// values.** They were the same one, which made every test on this page
    /// blind to the two being confused: an implementation comparing the record's
    /// asset against the commitment and vice versa would have passed all of
    /// them. `a_record_with_asset_and_commitment_transposed_is_refused` is the
    /// test that needs this, and it could not have existed before.
    fn genesis_fixture() -> (
        Vouched<HidingConfig>,
        uv_air::poseidon2::Digest,
        uv_air::poseidon2::Digest,
        Note,
        Lineage,
    ) {
        use p3_field::PrimeCharacteristicRing;
        let asset = [p3_baby_bear::BabyBear::from_u32(3); 8];
        let commitment = [p3_baby_bear::BabyBear::from_u32(5); 8];
        let note = uv_kernel2::note::Note::build(
            asset,
            uv_kernel2::amount::Amount(1),
            &uv_kernel2::keys::derive(&uv_kernel2::keys::WalletSeed([0u8; 32]), 0),
        );
        let hop = Hop {
            transfer: uv_kernel2::transfer::Transfer {
                // Must equal the commitment the receiver trusts, or the
                // `WrongGenesis` check refuses before the supply check runs.
                input_commitment: commitment,
                nullifier: asset,
                outputs: vec![],
                prev_history: history::GENESIS,
            },
            proof: Vec::new(),
        };
        (
            uv_air::prove::hiding_config(),
            asset,
            commitment,
            note,
            vec![hop],
        )
    }

    /// Build an issuance record for a genesis. The same three fields `accept`
    /// compares, so a test that publishes one and a receiver that looks for one
    /// cannot drift apart.
    fn record_for(
        asset: &Digest,
        commitment: &Digest,
        amount: u64,
    ) -> uv_kernel2::issuance::Issuance {
        uv_kernel2::issuance::Issuance {
            amount,
            asset: *asset,
            commitment: *commitment,
        }
    }

    /// **The secret-inflation attack, refused.** `formal/issuance.qnt`'s `lax`
    /// module finds this in two steps: mint without publishing, hand the coins
    /// over, and what a holder can spend exceeds what any reader of Bitcoin
    /// can see. Here the chain has no issuance records at all and the anchor
    /// claims 1000 — exactly the state after a secret mint.
    #[test]
    fn coins_from_an_unpublished_issuance_are_refused() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let chain = crate::chain::MockChain::new();
        assert!(matches!(
            accept(
                &cfg,
                &chain,
                &TrustAnchor {
                    asset: &asset,
                    genesis_commitment: &commitment,
                    issued_below: None,
                    genesis_amount: 1000,
                },
                &note,
                &lineage,
            ),
            Err(Rejected::GenesisNotIssued)
        ));
    }

    /// Publishing *an* issuance is not enough — it has to be the record for
    /// this genesis. Here the chain carries a record for a different one, which
    /// is the state of any chain with other people on it.
    #[test]
    fn a_genesis_whose_record_is_not_on_chain_is_refused() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let mut chain = crate::chain::MockChain::new();
        chain
            .publish_issuance(&record_for(&asset, &commitment, 1))
            .expect("mock publish");
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &commitment,
                issued_below: None,
                genesis_amount: 1_000_000,
            },
            &note,
            &lineage,
        );
        assert!(
            matches!(
                verdict,
                Err(Rejected::GenesisNotOnChain { records_seen: 1 })
            ),
            "got {verdict:?}"
        );
    }

    /// **The free-mint attack.** An attacker watches an honest issuance of 1000
    /// confirm, builds their own asset with a genesis note of the same amount,
    /// and hands out an anchor claiming it. Under an amount-only check — which
    /// is what this code did when the supply rule was first written — the
    /// honest record answers the attacker's check and they have minted 1000
    /// units without publishing anything. Amounts are round numbers; this
    /// collides by accident, let alone on purpose.
    #[test]
    fn an_attacker_cannot_mint_against_somebody_elses_issuance_record() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let honest = {
            use p3_field::PrimeCharacteristicRing;
            [p3_baby_bear::BabyBear::from_u32(77); 8]
        };
        let mut chain = crate::chain::MockChain::new();
        // The honest issuer publishes, correctly, for their own asset.
        chain
            .publish_issuance(&record_for(&honest, &honest, 1000))
            .expect("mock publish");
        // The attacker's anchor claims the same amount for a different asset.
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &commitment,
                issued_below: None,
                genesis_amount: 1000,
            },
            &note,
            &lineage,
        );
        assert!(
            matches!(verdict, Err(Rejected::GenesisNotOnChain { .. })),
            "an amount match against another asset's record must not pass, got {verdict:?}"
        );
    }

    /// **Two genesis notes under one asset id.** The issuer mints twice for the
    /// same asset and hands out two anchors. A record for the *other* genesis
    /// must not satisfy this one: the asset matches and the amount matches, and
    /// only the commitment differs. If the commitment were not on chain — the
    /// version of this record that carried a one-way hash could not put it
    /// there — both anchors would validate against one record and the chain
    /// would show half the coins that exist.
    #[test]
    fn a_second_genesis_under_the_same_asset_needs_its_own_record() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let other_genesis = {
            use p3_field::PrimeCharacteristicRing;
            [p3_baby_bear::BabyBear::from_u32(123); 8]
        };
        let mut chain = crate::chain::MockChain::new();
        // Same asset, same amount, different genesis note.
        chain
            .publish_issuance(&record_for(&asset, &other_genesis, 1000))
            .expect("mock publish");
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &commitment,
                issued_below: None,
                genesis_amount: 1000,
            },
            &note,
            &lineage,
        );
        assert!(
            matches!(verdict, Err(Rejected::GenesisNotOnChain { .. })),
            "another genesis of this asset must not answer for this one, got {verdict:?}"
        );
    }

    /// The control. Same fixture, same chain, with *this genesis's* record
    /// confirmed — so the refusals above are the supply rule doing the work and
    /// not some unrelated check that would have refused anything. This one gets
    /// past the supply gate and fails later, on the empty proof, which is the
    /// evidence that the gate let it through.
    #[test]
    fn the_genesis_record_for_this_asset_passes_the_supply_gate() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let mut chain = crate::chain::MockChain::new();
        chain
            .publish_issuance(&record_for(&asset, &commitment, 1000))
            .expect("mock publish");
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &commitment,
                issued_below: None,
                genesis_amount: 1000,
            },
            &note,
            &lineage,
        );
        assert!(
            !matches!(
                verdict,
                Err(Rejected::GenesisNotIssued) | Err(Rejected::GenesisNotOnChain { .. })
            ),
            "the supply gate must not be what refuses this, got {verdict:?}"
        );
    }

    /// **The asset and the commitment are not interchangeable.** The fixture
    /// gives them distinct values precisely so this can be asked: a record with
    /// the two fields transposed must not satisfy the check. Without this, an
    /// implementation that compared `i.asset` against the commitment and
    /// `i.commitment` against the asset would pass every other test on this
    /// page, because they all used one value for both.
    #[test]
    fn a_record_with_asset_and_commitment_transposed_is_refused() {
        let (cfg, asset, commitment, note, lineage) = genesis_fixture();
        let mut chain = crate::chain::MockChain::new();
        chain
            .publish_issuance(&record_for(&commitment, &asset, 1000))
            .expect("mock publish");
        let verdict = accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &commitment,
                issued_below: None,
                genesis_amount: 1000,
            },
            &note,
            &lineage,
        );
        assert!(
            matches!(verdict, Err(Rejected::GenesisNotOnChain { .. })),
            "got {verdict:?}"
        );
    }

    /// A lineage is attacker-chosen in length, and a receiver verifies every
    /// hop of it. The cap is refused before any proof is deserialized, which is
    /// what makes it a defence rather than a formality.
    #[test]
    fn an_absurdly_long_lineage_is_refused_before_any_proof_work() {
        let hop = Hop {
            transfer: uv_kernel2::transfer::Transfer {
                input_commitment: [p3_baby_bear::BabyBear::default(); 8],
                nullifier: [p3_baby_bear::BabyBear::default(); 8],
                outputs: vec![],
                prev_history: history::GENESIS,
            },
            // Deliberately not a proof. Reaching a verify call would panic or
            // fail here, so if this test passes the cap ran first.
            proof: Vec::new(),
        };
        let lineage: Lineage = vec![hop; MAX_LINEAGE + 1];
        let chain = crate::chain::MockChain::new();
        let cfg = uv_air::prove::hiding_config();
        let asset = [p3_baby_bear::BabyBear::default(); 8];
        let note = uv_kernel2::note::Note::build(
            asset,
            uv_kernel2::amount::Amount(1),
            &uv_kernel2::keys::derive(&uv_kernel2::keys::WalletSeed([0u8; 32]), 0),
        );
        assert!(matches!(
            accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset,
                genesis_commitment: &asset,
                issued_below: None,
                // The cap refuses before any chain lookup — that is the point
                // of the test — so this value is never consulted.
                genesis_amount: 1,
            },
            &note,
            &lineage,
        ),
            Err(Rejected::TooLong(n)) if n == MAX_LINEAGE + 1
        ));
    }
}
