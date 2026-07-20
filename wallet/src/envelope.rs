//! Hybrid post-quantum note encryption: ML-KEM-768 + X25519 → HKDF → AEAD.
//!
//! Confidentiality is off the money path, so this is the one place lattice
//! (ML-KEM) and classical (X25519) assumptions appear — combined, so an
//! attacker must break *both*. Each message derives a fresh AEAD key from an
//! ephemeral encapsulation, so a zero nonce is safe (the key is single-use).
//!
//! Public scan key wire format (`AddressRecord::scan_kem_pk`):
//! `mlkem768_ek (1184 B) ‖ x25519_pk (32 B)`.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecret};

const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X_PK_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"uv/envelope/v1";

pub type MlKemDk = <MlKem768 as KemCore>::DecapsulationKey;
pub type MlKemEk = <MlKem768 as KemCore>::EncapsulationKey;

/// A recipient's scan keypair (secret side). Held by the wallet.
pub struct ScanSecret {
    pub mlkem_dk: MlKemDk,
    pub x_secret: XSecret,
}

/// A recipient's scan public keys (what senders encrypt to).
pub struct ScanPublic {
    pub mlkem_ek: MlKemEk,
    pub x_public: XPublicKey,
}

#[derive(Debug)]
pub enum EnvelopeError {
    BadScanKey,
    BadCiphertext,
    Decrypt,
}

/// Generate a fresh scan keypair from the OS RNG.
pub fn generate_scan() -> (ScanSecret, ScanPublic) {
    generate_scan_from(&mut OsRng)
}

/// Generate a scan keypair from a caller-supplied RNG — used to derive a
/// persistent identity deterministically from a stored seed.
pub fn generate_scan_from<R: rand::RngCore + rand::CryptoRng>(
    rng: &mut R,
) -> (ScanSecret, ScanPublic) {
    let (dk, ek) = MlKem768::generate(rng);
    let xsk = XSecret::random_from_rng(&mut *rng);
    let xpk = XPublicKey::from(&xsk);
    (
        ScanSecret { mlkem_dk: dk, x_secret: xsk },
        ScanPublic { mlkem_ek: ek, x_public: xpk },
    )
}

impl ScanPublic {
    /// Serialize to the `scan_kem_pk` wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MLKEM_EK_LEN + X_PK_LEN);
        out.extend_from_slice(self.mlkem_ek.as_bytes().as_slice());
        out.extend_from_slice(self.x_public.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() != MLKEM_EK_LEN + X_PK_LEN {
            return Err(EnvelopeError::BadScanKey);
        }
        let ek_enc = ml_kem::Encoded::<MlKemEk>::try_from(&bytes[..MLKEM_EK_LEN])
            .map_err(|_| EnvelopeError::BadScanKey)?;
        let mlkem_ek = MlKemEk::from_bytes(&ek_enc);
        let mut xb = [0u8; X_PK_LEN];
        xb.copy_from_slice(&bytes[MLKEM_EK_LEN..]);
        Ok(ScanPublic { mlkem_ek, x_public: XPublicKey::from(xb) })
    }
}

fn derive_key(ss_mlkem: &[u8], ss_x: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_mlkem.len() + ss_x.len());
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ss_x);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).expect("32 is a valid OKM length");
    okm
}

/// Encrypt `plaintext` to a recipient's scan public keys. Output wire format:
/// `mlkem_ct (1088 B) ‖ x25519_ephemeral_pk (32 B) ‖ aead_ct`.
pub fn seal(to: &ScanPublic, plaintext: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let (ct_mlkem, ss_mlkem) = to.mlkem_ek.encapsulate(&mut rng).expect("encapsulation");
    let eph = XSecret::random_from_rng(&mut rng);
    let eph_pub = XPublicKey::from(&eph);
    let ss_x = eph.diffie_hellman(&to.x_public);

    let key = derive_key(ss_mlkem.as_slice(), ss_x.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let aead_ct = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
        .expect("AEAD encryption is infallible for valid inputs");

    let mut out = Vec::with_capacity(MLKEM_CT_LEN + X_PK_LEN + aead_ct.len());
    out.extend_from_slice(ct_mlkem.as_slice());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&aead_ct);
    out
}

/// Decrypt an envelope with the recipient's scan secret. Returns the plaintext,
/// or `Err` if this envelope was not sealed to us (which is how trial-scanning
/// silently skips others' payments).
pub fn open(sk: &ScanSecret, envelope: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.len() < MLKEM_CT_LEN + X_PK_LEN {
        return Err(EnvelopeError::BadCiphertext);
    }
    let ct_enc = ml_kem::Ciphertext::<MlKem768>::try_from(&envelope[..MLKEM_CT_LEN])
        .map_err(|_| EnvelopeError::BadCiphertext)?;
    let ss_mlkem = sk.mlkem_dk.decapsulate(&ct_enc).map_err(|_| EnvelopeError::Decrypt)?;

    let mut eph = [0u8; X_PK_LEN];
    eph.copy_from_slice(&envelope[MLKEM_CT_LEN..MLKEM_CT_LEN + X_PK_LEN]);
    let ss_x = sk.x_secret.diffie_hellman(&XPublicKey::from(eph));

    let key = derive_key(ss_mlkem.as_slice(), ss_x.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), &envelope[MLKEM_CT_LEN + X_PK_LEN..])
        .map_err(|_| EnvelopeError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_key_rejected() {
        let (sk, pk) = generate_scan();
        let msg = b"a 300 UVD note for Bob";
        let env = seal(&pk, msg);
        assert_eq!(open(&sk, &env).unwrap(), msg);

        let (other_sk, _) = generate_scan();
        assert!(open(&other_sk, &env).is_err(), "not sealed to us → skip");
    }

    #[test]
    fn scan_public_wire_roundtrips() {
        let (_, pk) = generate_scan();
        let bytes = pk.to_bytes();
        let pk2 = ScanPublic::from_bytes(&bytes).unwrap();
        // re-seal to the reconstructed key and open with the original secret
        let (sk, pk_orig) = generate_scan();
        let env = seal(&ScanPublic::from_bytes(&pk_orig.to_bytes()).unwrap(), b"hi");
        assert_eq!(open(&sk, &env).unwrap(), b"hi");
        let _ = pk2;
    }
}
