//! The transfer bundle: what a sender delivers to a recipient, encrypted to
//! their scan key. The 64-byte record goes on Bitcoin; this travels over the
//! transport layer (Nostr / file).

use serde::{Deserialize, Serialize};

use ultraviolet_kernel::note::Note;

use crate::envelope::{open, seal, ScanPublic, ScanSecret};

/// Cleartext bundle contents (sealed before it touches the wire).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    /// SP1 compressed recursive proof of the transfer's whole history (opaque).
    pub proof_bytes: Vec<u8>,
    /// `HopOutput::encode()` for this transfer — lets the receiver chain their
    /// own next spend and recompute the public-values digest.
    pub hop_output_bytes: Vec<u8>,
    /// The note this bundle pays to the recipient (their new output note).
    pub output_note: Note,
    /// The 64-byte on-chain record for this transfer (`Vec` for serde).
    pub record: Vec<u8>,
}

impl Bundle {
    /// Serialize and encrypt to a recipient's scan public key.
    pub fn seal_to(&self, to: &ScanPublic) -> Vec<u8> {
        let plain = bincode::serialize(self).expect("serialize bundle");
        seal(to, &plain)
    }

    /// Decrypt with our scan secret and deserialize. `Err` (or a deserialize
    /// failure) means this bundle was not for us — skip it.
    pub fn open_with(sk: &ScanSecret, ciphertext: &[u8]) -> Option<Bundle> {
        let plain = open(sk, ciphertext).ok()?;
        bincode::deserialize(&plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::generate_scan;

    #[test]
    fn bundle_seals_to_recipient_and_others_cannot_open() {
        let (sk, pk) = generate_scan();
        let bundle = Bundle {
            proof_bytes: vec![1, 2, 3, 4],
            hop_output_bytes: vec![5, 6, 7],
            output_note: Note {
                contract_id: [1; 32],
                value: 300,
                owner_key: [2; 32],
                randomness: [3; 32],
            },
            record: vec![9u8; 64],
        };
        let ct = bundle.seal_to(&pk);
        let got = Bundle::open_with(&sk, &ct).expect("recipient opens");
        assert_eq!(got.output_note.value, 300);
        assert_eq!(got.record.len(), 64);

        let (other, _) = generate_scan();
        assert!(Bundle::open_with(&other, &ct).is_none(), "others can't open");
    }
}
