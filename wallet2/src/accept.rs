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
//! anchor is published — is spec/02+09 territory; this module takes the
//! anchor as given.

use bincode::Options as _;
use uv_air::prove::{HidingConfig, Vouched};
use uv_air::wots::Digest;
use uv_kernel2::history;
use uv_kernel2::note::Note;
use uv_kernel2::transfer::Transfer;
use uv_kernel2::transfer_prove::{verify_hiding, RefusedHiding};

use crate::chain::{required_confirmations, Chain, Lookup, Occurrence};

/// One hop as it travels: the public transfer and its hiding proof.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Hop {
    pub transfer: Transfer,
    /// Serialized `HidingTransferProof`.
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
    /// The lineage is longer than any real coin's history plausibly is.
    ///
    /// A receiver verifies *every* hop, so an unbounded lineage is unbounded
    /// attacker-chosen work. See [`MAX_LINEAGE`].
    TooLong(usize),
}

impl Rejected {
    /// Will this note ever become acceptable, or is it dead?
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
    pub fn is_permanent(&self) -> bool {
        !matches!(
            self,
            Rejected::NoRecord(_) | Rejected::InsufficientDepth(_) | Rejected::ViewIncomplete(_)
        )
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

/// Validate `note` against its `lineage` and the chain, at the receiver's
/// confirmation policy. On `Ok`, the note is safe to hold and re-spend.
pub fn accept(
    config: &Vouched<HidingConfig>,
    chain: &(impl Chain + ?Sized),
    asset: &Digest,
    genesis_commitment: &Digest,
    note: &Note,
    lineage: &Lineage,
    // The height below which this asset had not been issued, if known. `None`
    // means an anchor written before issuance heights existed — in which case
    // the floor cannot be checked and is not.
    issued_below: Option<u64>,
) -> Result<(), Rejected> {
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
        let proof = bincode::DefaultOptions::new()
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
            Rejected::ViewIncomplete(2),
        ] {
            assert!(
                !transient.is_permanent(),
                "{transient:?} can still become valid — it must be kept"
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
            Rejected::TooLong(9_999),
        ] {
            assert!(
                permanent.is_permanent(),
                "{permanent:?} can never become valid — it must be discarded"
            );
        }
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
                &asset,
                &asset,
                &note,
                &vec![hop.clone()],
                Some(400)
            ),
            Err(Rejected::ViewIncomplete(_))
        ));
        // Floor 300, same asset: the view reaches below the issuance, so the
        // floor is not what stops this one.
        assert!(!matches!(
            accept(
                &cfg,
                &Narrow(300),
                &asset,
                &asset,
                &note,
                &vec![hop],
                Some(400)
            ),
            Err(Rejected::ViewIncomplete(_))
        ));
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
            accept(&cfg, &chain, &asset, &asset, &note, &lineage, None),
            Err(Rejected::TooLong(n)) if n == MAX_LINEAGE + 1
        ));
    }
}
