//! The trust anchor: what a receiver must know about an asset before any
//! payment of it can be validated.
//!
//! Lives here because both callers need it whole: the CLI writes it at `issue`
//! and reads it at `scan`/`send`/`status`, and the phone must read the same
//! file with the same refusals — an anchor is the root of every acceptance, so
//! two parsers of it would be two chances to disagree about what "trusted"
//! means.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::home::anchor_path;
use crate::{Error, Result};

#[derive(Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub asset_hex: String,
    pub commitment_hex: String,
    /// The chain height below which none of this asset's records can exist.
    ///
    /// A receiver whose chain view starts *above* this cannot rule out an
    /// earlier conflicting record, which is how an index with too high a floor
    /// makes a double-spend look valid. `Option`, not a defaulted `u64`: an
    /// anchor written before this existed must read as "unknown" and refuse a
    /// non-zero floor, not as "height 0" that quietly passes.
    ///
    /// Stamped at *tip minus a reorg margin*, never the bare tip — the tip at
    /// issue time can itself be reorged away, and a record could then land
    /// below the floor. Off by one reorg is a silent fail-open.
    #[serde(default)]
    pub issued_below: Option<u64>,
    /// The genesis note's opening, so a receiver can check the commitment
    /// really holds the amount the chain says was issued.
    ///
    /// **Required.** This was an `Option` so that anchors written before
    /// issuance went on chain could still validate, and an absent opening meant
    /// the supply check was skipped. That is not a missing field, it is a way
    /// to spell "trust me" — and `serde` would supply it silently for any file
    /// that omitted the key. An anchor without an opening is now refused at
    /// import, where a person reads why, rather than accepted into a wallet
    /// that quietly stops checking.
    ///
    /// Publishing this costs the issuer nothing they wanted kept: it is their
    /// own note, and its amount is the number being audited. It is the one note
    /// in an asset whose value is meant to be public (`SPEC.md` §9).
    pub genesis: GenesisOpening,
}

/// Everything needed to recompute the genesis commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct GenesisOpening {
    pub amount: u64,
    pub nullifier_anchor_hex: String,
    pub randomness_hex: String,
}

/// Read the home's anchor, if one exists.
///
/// `Ok(None)` is "no anchor yet" — a wallet that cannot validate anything, a
/// state the caller reports rather than an error. A file that exists but does
/// not parse is an error: an unreadable trust root must never be mistaken for
/// an absent one.
pub fn read(home: &Path) -> Result<Option<Anchor>> {
    let p = anchor_path(home);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Storage(format!("cannot read {}: {e}", p.display()))),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| Error::BadInput(format!("{}: not a readable anchor: {e}", p.display())))
}

/// Write the home's anchor.
pub fn write(home: &Path, anchor: &Anchor) -> Result<()> {
    let p = anchor_path(home);
    let bytes = serde_json::to_vec_pretty(anchor)
        .map_err(|e| Error::Storage(format!("serialize anchor: {e}")))?;
    std::fs::write(&p, bytes).map_err(|e| Error::Storage(format!("write {}: {e}", p.display())))
}

/// Parse an anchor from bytes, with the one diagnosis that matters spelled
/// out: a file that is anchor-shaped but lacks the genesis opening.
///
/// `genesis` used to be `#[serde(default)] Option<GenesisOpening>`, so a file
/// omitting it parsed fine and installed a wallet that silently stopped
/// checking supply. Now the field is required, parsing fails here, and the
/// failure is a sentence a person can act on rather than a check that never
/// ran.
pub fn parse(bytes: &[u8]) -> Result<Anchor> {
    serde_json::from_slice(bytes).map_err(|e| {
        if String::from_utf8_lossy(bytes).contains("\"asset_hex\"") {
            Error::BadInput(format!(
                "this anchor has no genesis opening: {e}\n\nAnchors written before \
                 issuance went on chain cannot be validated — there is no amount to \
                 check against Bitcoin, and accepting one would mean holding coins \
                 whose supply nobody can count. Re-issue the asset; its id changes, \
                 which is the intended consequence (SPEC.md section 9)."
            ))
        } else {
            Error::BadInput(format!("not an anchor file: {e}"))
        }
    })
}

/// What an import did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    Installed,
    /// Same asset, same genesis, differing floors: the lower floor was kept.
    /// The floor is a security parameter — a *higher* one hides records below
    /// it, which is how a double-spend passes.
    FloorMergedDown {
        had: Option<u64>,
        incoming: Option<u64>,
        kept: Option<u64>,
    },
}

/// Install an incoming anchor, refusing every silent replacement.
///
/// A home holds one anchor, so overwriting it with a *different asset*
/// orphans every note of the old one — they stay in the wallet and quietly
/// stop validating. And an anchor with the same asset id but a **different
/// genesis** is a supply bug, not a tidiness one: `accept` decides a
/// lineage's origin by byte-equality against this one commitment, so two
/// payees holding two anchors under one id validate two disjoint genesis
/// notes and each believes they hold the asset — two supplies,
/// indistinguishable notes, nothing anywhere to notice. Refused rather than
/// merged: there is no rule for choosing between two genesis notes, and
/// picking one silently is how a holder ends up validating against an
/// issuance they never agreed to.
pub fn import(home: &Path, incoming: Anchor) -> Result<ImportOutcome> {
    let canonical = |s: &str| -> bool {
        hex::decode(s)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|arr| uv_kernel2::digest::decode(&arr))
            .is_some()
    };
    if !canonical(&incoming.asset_hex) || !canonical(&incoming.commitment_hex) {
        return Err(Error::BadInput(
            "anchor fields are not canonical digests; refusing".into(),
        ));
    }

    if let Some(existing) = read(home)? {
        if existing.asset_hex != incoming.asset_hex {
            return Err(Error::Refused(format!(
                "this home already holds a different asset:\n  have {}\n  new  {}\n\
                 Importing would orphan every note of the one you have — they would stay\n\
                 in the wallet and quietly stop validating. Use a separate home.",
                existing.asset_hex, incoming.asset_hex
            )));
        }
        if existing.commitment_hex != incoming.commitment_hex {
            return Err(Error::Refused(format!(
                "SAME asset id, DIFFERENT genesis — refusing.\n  have {}\n  new  {}\n\
                 One asset has one issuance. Two anchors claiming the same asset with\n\
                 different genesis notes means one of them is not from the issuer, or the\n\
                 issuer issued twice under one id. Either way, taking the new one would\n\
                 silently change which coins this wallet considers real.",
                existing.commitment_hex, incoming.commitment_hex
            )));
        }
        if existing.issued_below != incoming.issued_below {
            let kept = match (existing.issued_below, incoming.issued_below) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            };
            let merged = Anchor {
                asset_hex: incoming.asset_hex.clone(),
                commitment_hex: incoming.commitment_hex.clone(),
                issued_below: kept,
                genesis: incoming.genesis.clone(),
            };
            write(home, &merged)?;
            return Ok(ImportOutcome::FloorMergedDown {
                had: existing.issued_below,
                incoming: incoming.issued_below,
                kept,
            });
        }
    }
    write(home, &incoming)?;
    Ok(ImportOutcome::Installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Anchor {
        Anchor {
            asset_hex: "aa".into(),
            commitment_hex: "bb".into(),
            issued_below: Some(7),
            genesis: GenesisOpening {
                amount: 1000,
                nullifier_anchor_hex: "cc".into(),
                randomness_hex: "dd".into(),
            },
        }
    }

    #[test]
    fn round_trips_through_the_home() {
        let dir = std::env::temp_dir().join(format!("uv-anchor-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write(&dir, &sample()).unwrap();
        let back = read(&dir).unwrap().expect("just written");
        assert_eq!(back.asset_hex, "aa");
        assert_eq!(back.issued_below, Some(7));
        assert_eq!(back.genesis.amount, 1000);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Absent is a state; unreadable is an error. Confusing the two turns a
    /// corrupted trust root into "no anchor yet", which validates nothing and
    /// says nothing.
    #[test]
    fn absent_is_none_but_garbage_is_an_error() {
        let dir = std::env::temp_dir().join(format!("uv-anchor-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read(&dir).unwrap().is_none(), "no file yet");
        std::fs::write(crate::home::anchor_path(&dir), b"not json").unwrap();
        assert!(
            read(&dir).is_err(),
            "an unreadable anchor must not read as absent"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An anchor written before floors existed reads as "unknown", never as
    /// height 0 — serde's default supplies `None`, and the field's doc says
    /// why that is the only safe default.
    #[test]
    fn a_floorless_anchor_reads_as_unknown() {
        let json = r#"{"asset_hex":"aa","commitment_hex":"bb",
            "genesis":{"amount":5,"nullifier_anchor_hex":"cc","randomness_hex":"dd"}}"#;
        let a: Anchor = serde_json::from_str(json).unwrap();
        assert_eq!(a.issued_below, None);
    }
}
