//! Encrypting the wallet file at rest (spec/99, closed).
//!
//! The wallet file holds two things that must survive a stolen laptop: the
//! seed, from which every note key derives, and the sign log, which records
//! the exact payload each one-time key signed. Losing the seed loses the
//! money. Losing the log alone loses only in-flight payments — but it is *not*
//! a cache, because replaying a logged payload is the one safe response to a
//! record that lost its race (spec/02).
//!
//! Both are now encrypted under a passphrase: Argon2id to turn the passphrase
//! into a key, ChaCha20-Poly1305 to seal the file. The salt and nonce are
//! stored in the clear alongside the ciphertext, which is standard and safe —
//! neither is secret, and both must be fresh per write.
//!
//! **This is off the money path.** The "hashes only" rule (spec/01) governs
//! what can steal or forge money in the protocol; it does not govern the disk.
//! Breaking this gets someone who already has your file a chance at your
//! passphrase, which is the ordinary threat model for wallet encryption.
//!
//! Files stay 0600 as well. Encryption is defence in depth over the file mode,
//! not a replacement for it.

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};

/// A sealed wallet file. The salt and nonce are public by design.
///
/// Raw bytes rather than hex. A wallet holds every note's lineage, and a
/// lineage is mostly proof bytes — hex doubled the ciphertext for no benefit,
/// since nothing reads this by eye. Serialized with a binary encoder for the
/// same reason.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    /// Format marker, so a future change can be detected rather than guessed.
    pub v: u8,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
}

#[derive(Debug)]
pub enum VaultError {
    /// Wrong passphrase, or the file was altered. Indistinguishable on
    /// purpose: an authenticated cipher cannot tell you which.
    CannotOpen,
    Malformed,
}

const VERSION: u8 = 1;

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    // Argon2id at the crate's defaults: memory-hard, so a stolen file cannot
    // be attacked at GPU speed the way a plain hash could.
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("argon2 with a 32-byte output");
    key
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use std::io::Read;
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom")
        .expect("urandom")
        .read_exact(&mut b)
        .expect("read urandom");
    b
}

/// Seal `plaintext` under `passphrase`. A fresh salt and nonce every time —
/// reusing a nonce with the same key would be catastrophic for ChaCha20, and
/// the only way to guarantee freshness is to never reuse the key material.
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Vault {
    let salt: [u8; 16] = random_bytes();
    let nonce_bytes: [u8; 12] = random_bytes();
    let key = derive_key(passphrase, &salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("chacha20poly1305 encrypt");
    Vault {
        v: VERSION,
        salt: salt.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ct,
    }
}

/// Open a sealed wallet. Fails identically for a wrong passphrase and a
/// tampered file — the authentication tag does not distinguish them.
pub fn open(passphrase: &str, vault: &Vault) -> Result<Vec<u8>, VaultError> {
    if vault.v != VERSION {
        return Err(VaultError::Malformed);
    }
    if vault.nonce.len() != 12 {
        return Err(VaultError::Malformed);
    }
    let (salt, nonce, ct) = (&vault.salt, &vault.nonce, &vault.ct);
    let key = derive_key(passphrase, salt);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct.as_ref())
        .map_err(|_| VaultError::CannotOpen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let v = seal("correct horse battery staple", b"the seed and the log");
        assert_eq!(
            open("correct horse battery staple", &v).unwrap(),
            b"the seed and the log"
        );
    }

    #[test]
    fn a_wrong_passphrase_cannot_open_it() {
        let v = seal("right", b"secret");
        assert!(matches!(open("wrong", &v), Err(VaultError::CannotOpen)));
    }

    #[test]
    fn tampering_is_detected() {
        let mut v = seal("pw", b"secret");
        // Flip one ciphertext byte: the authentication tag must catch it.
        let mut ct = v.ct.clone();
        ct[0] ^= 1;
        v.ct = ct;
        assert!(matches!(open("pw", &v), Err(VaultError::CannotOpen)));
    }

    #[test]
    fn every_seal_is_unique() {
        // Same passphrase, same plaintext, different salt and nonce — so two
        // wallet files never reveal that they hold identical contents.
        let a = seal("pw", b"same");
        let b = seal("pw", b"same");
        assert_ne!(a.ct, b.ct);
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
    }
}
