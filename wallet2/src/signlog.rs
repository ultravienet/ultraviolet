//! The sign-log: never re-sign, never forget what you signed.
//!
//! `formal/onetime.qnt`, made code. A WOTS+ key that signs two different
//! messages reveals its private key — total loss. A wallet that merely
//! remembers *that* it signed must refuse forever when the record loses a
//! race, freezing live money. The only discipline that is both safe and live
//! is the one implemented here: **record the exact signed payload, and when a
//! signed-but-unsettled note must be rebroadcast, replay those identical
//! bytes** — WOTS+ signing is deterministic (pinned by
//! `uv_air::wots::tests::signing_is_deterministic`), so the replay reproduces
//! the one signature that already exists and reveals nothing new.
//!
//! Consequences (spec/02, normative):
//! - the log is written **before** the first broadcast, not after;
//! - the log is write-once per note: logging a *different* payload for a note
//!   that already has one is refused — that refusal IS the never-re-sign rule;
//! - the log is part of the wallet backup. Losing it costs only in-flight
//!   transfers (the seed plus a chain rescan recovers everything settled),
//!   but "write down the seed" alone no longer covers the signing window.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uv_kernel2::transfer::Transfer;

/// The exact spend a note produced, stored so a lost-record retry resends the
/// **identical** transfer (same nullifier and bundle hash → same record).
///
/// With proof-native authorization there is no signature, so re-proving would be
/// safe — but the change note is derived from a fresh index, so re-*preparing*
/// would build a different transfer and a different record. This cache keeps the
/// spend byte-for-byte, which is what a first-occurrence race needs. (The
/// key-disclosure reason this log originally existed is gone with WOTS+; the
/// idempotency reason is not, which is why it survives the cutover.)
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedSpend {
    pub transfer: Transfer,
    /// Serialized `HidingAuthProtoProof`.
    pub proof: Vec<u8>,
}

/// Why the log refused a write.
#[derive(Debug, PartialEq, Eq)]
pub enum LogError {
    /// The note already signed a DIFFERENT payload. Proceeding would be key
    /// disclosure; the caller must replay the stored entry instead.
    NeverResign,
}

/// A persisted map from **derivation index** to the one spend that index's key
/// ever signed.
///
/// **The key is the index, not the note commitment, and the difference is the
/// whole point.** A WOTS+ signing key is derived from `(wallet seed,
/// key_index)`, so the index *is* the unit that may sign exactly once. Keying
/// this log on the input note's commitment instead assumed index and note were
/// one-to-one — and nothing enforced that. Two payments to the same address
/// slot with different amounts produce two notes with different commitments and
/// the *same* index; the log saw two distinct keys and permitted signing both,
/// with one key. That is total key disclosure, and it needed no attacker: two
/// payers holding the same address file each track their own slot reservations
/// and both start at zero.
///
/// Keyed on the index, every one of those routes is a `NeverResign` refusal by
/// construction rather than by a coincidence holding.
///
/// In-memory here; persistence is a serialization concern owned by the layer
/// that owns the wallet's storage. What is consensus-critical is the write-once
/// semantics, which live here.
#[derive(Default, Serialize, Deserialize)]
pub struct SignLog {
    /// Format marker. An older log keyed by commitment is unreadable rather
    /// than half-readable: silently reading it as empty would remove the only
    /// thing standing between a restored wallet and a second signature.
    #[serde(default)]
    version: u32,
    /// Keyed by derivation index, as a decimal string — JSON requires string
    /// keys, and the log is meant to be inspectable.
    entries: HashMap<String, SignedSpend>,
}

/// Bump when the key or the entry shape changes.
pub const LOG_VERSION: u32 = 2;

fn key(index: u64) -> String {
    index.to_string()
}

impl SignLog {
    pub fn new() -> Self {
        Self {
            version: LOG_VERSION,
            entries: HashMap::new(),
        }
    }

    /// Is this a log this code can safely reason about?
    ///
    /// A log written before the key changed from commitment to index looks
    /// perfectly well-formed and answers every question wrongly. The caller
    /// must refuse it rather than treat an unrecognised version as empty.
    pub fn version_ok(&self) -> bool {
        self.version == LOG_VERSION
    }

    /// The spend this derivation index's key already signed, if any.
    pub fn get(&self, key_index: u64) -> Option<&SignedSpend> {
        self.entries.get(&key(key_index))
    }

    /// Log a spend. Write-once *per signing key*: a second put with the
    /// identical payload is an idempotent no-op (replays hit this), a different
    /// payload with the same key is refused.
    pub fn put(&mut self, key_index: u64, spend: SignedSpend) -> Result<(), LogError> {
        let k = key(key_index);
        match self.entries.get(&k) {
            None => {
                self.entries.insert(k, spend);
                Ok(())
            }
            Some(existing) if existing.transfer == spend.transfer => Ok(()),
            Some(_) => Err(LogError::NeverResign),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use uv_air::wots::Digest;

    fn d(t: u32) -> Digest {
        [BabyBear::from_u32(t); 8]
    }

    fn spend(input: Digest, out: u32) -> SignedSpend {
        SignedSpend {
            transfer: Transfer {
                input_commitment: input,
                nullifier: d(2),
                outputs: vec![d(out), d(4)],
                prev_history: d(5),
            },
            proof: vec![1, 2, 3],
        }
    }

    #[test]
    fn replaying_the_same_payload_is_fine_a_different_one_is_not() {
        let mut log = SignLog::new();
        log.put(5, spend(d(1), 30)).unwrap();
        // Identical payload: idempotent (this is the rebroadcast path).
        log.put(5, spend(d(1), 30)).unwrap();
        // A different payload for the same *key*: the exact mistake that
        // reveals a WOTS+ private key. Refused.
        assert_eq!(log.put(5, spend(d(1), 31)), Err(LogError::NeverResign));
        // The stored entry is the original, untouched.
        assert_eq!(log.get(5).unwrap().transfer.outputs[0], d(30));
    }

    /// The reason the key is the derivation index and not the note commitment.
    ///
    /// Two payments to one address slot produce two notes with different
    /// commitments and the *same* signing key. Keyed by commitment, the log saw
    /// two unrelated entries and permitted both — one key, two signatures, total
    /// disclosure. Keyed by index it is a refusal, and no attacker is needed to
    /// reach it: two payers sharing an address file both start at slot zero.
    #[test]
    fn two_notes_sharing_a_signing_key_cannot_both_be_signed() {
        let mut log = SignLog::new();
        log.put(3, spend(d(100), 1)).unwrap();
        assert_eq!(
            log.put(3, spend(d(200), 2)),
            Err(LogError::NeverResign),
            "different note, same derivation index, therefore the same one-time key"
        );
    }

    /// A log written before the key changed answers every question wrongly
    /// while looking perfectly well-formed. It must be refused, not read.
    #[test]
    fn an_old_format_log_is_refused_rather_than_read() {
        let fresh = SignLog::new();
        assert!(fresh.version_ok());
        let old: SignLog = serde_json::from_str(r#"{"entries":{}}"#).unwrap();
        assert!(!old.version_ok(), "a log with no version must not pass");
    }

    #[test]
    fn the_log_round_trips_through_serialization() {
        let mut log = SignLog::new();
        log.put(7, spend(d(7), 42)).unwrap();
        let bytes = bincode::serialize(&log).unwrap();
        let back: SignLog = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.get(7).unwrap().transfer.outputs[0], d(42));
        assert!(back.version_ok(), "the version must survive a round trip");
    }
}
