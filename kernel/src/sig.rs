//! Signature abstraction and the SLH-DSA-SHA2-128s implementation.
//!
//! Ownership signatures are hash-based: SLH-DSA-128s by default (stateless,
//! misuse-resistant; 32-byte public keys, 7,856-byte signatures, hash-only
//! verification — spec/01-CRYPTO.md). WOTS+ (the one-time performance profile)
//! and the SP1 in-circuit verifier land in later revisions.

use crate::hash::Hash256;

/// Verifies a signature over a 32-byte payload hash.
pub trait Verifier {
    /// Returns `true` iff `sig` is a valid signature over `payload` for this
    /// verifier's public key.
    fn verify(&self, payload: &Hash256, sig: &[u8]) -> bool;
}

/// Signs a 32-byte payload hash.
pub trait Signer {
    fn sign(&self, payload: &Hash256) -> Vec<u8>;
}

#[cfg(feature = "slh")]
pub mod slh {
    //! SLH-DSA-SHA2-128s (FIPS 205) via the `fips205` crate.

    use super::{Hash256, Signer, Verifier};
    use fips205::slh_dsa_sha2_128s;
    use fips205::traits::{SerDes, Signer as _, Verifier as _};

    /// Domain/context string binding signatures to this protocol version.
    const CTX: &[u8] = b"uv/sig/v1";

    pub const PK_LEN: usize = slh_dsa_sha2_128s::PK_LEN; // 32
    pub const SIG_LEN: usize = slh_dsa_sha2_128s::SIG_LEN; // 7_856

    /// An SLH-DSA-128s keypair (signing side).
    pub struct SlhKeypair {
        sk: slh_dsa_sha2_128s::PrivateKey,
        pk: slh_dsa_sha2_128s::PublicKey,
    }

    /// An SLH-DSA-128s public key (verifying side).
    pub struct SlhPublicKey(slh_dsa_sha2_128s::PublicKey);

    impl SlhKeypair {
        /// Generate a fresh keypair from the OS RNG.
        pub fn generate() -> Result<Self, &'static str> {
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen()?;
            Ok(SlhKeypair { sk, pk })
        }

        /// Generate deterministically from a caller-supplied RNG. Used by
        /// wallets to derive a persistent identity from a stored seed.
        pub fn generate_with_rng<R: rand_core::CryptoRngCore>(
            rng: &mut R,
        ) -> Result<Self, &'static str> {
            let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(rng)?;
            Ok(SlhKeypair { sk, pk })
        }

        pub fn public_key(&self) -> SlhPublicKey {
            SlhPublicKey(self.pk.clone())
        }

        /// The 32-byte serialized public key (this is what `Note.owner_key`
        /// commits to, hashed).
        pub fn public_key_bytes(&self) -> [u8; PK_LEN] {
            self.pk.clone().into_bytes()
        }

        /// Deterministic (non-hedged) signature. Used where a stable output is
        /// wanted — e.g. a published address record, so the same identity
        /// always yields the same address string.
        pub fn sign_deterministic(&self, payload: &Hash256) -> Vec<u8> {
            self.sk
                .try_sign(payload, CTX, false)
                .expect("SLH-DSA signing is infallible for valid keys")
                .to_vec()
        }
    }

    impl Signer for SlhKeypair {
        fn sign(&self, payload: &Hash256) -> Vec<u8> {
            // Hedged signing (the FIPS 205 default) — randomized, so leaking
            // two signatures over one payload reveals nothing extra.
            self.sk
                .try_sign(payload, CTX, true)
                .expect("SLH-DSA signing is infallible for valid keys")
                .to_vec()
        }
    }

    impl Verifier for SlhPublicKey {
        fn verify(&self, payload: &Hash256, sig: &[u8]) -> bool {
            let Ok(sig): Result<[u8; SIG_LEN], _> = sig.try_into() else {
                return false;
            };
            self.0.verify(payload, &sig, CTX)
        }
    }

    impl SlhPublicKey {
        pub fn from_bytes(bytes: &[u8; PK_LEN]) -> Result<Self, &'static str> {
            slh_dsa_sha2_128s::PublicKey::try_from_bytes(bytes).map(SlhPublicKey)
        }

        pub fn to_bytes(&self) -> [u8; PK_LEN] {
            self.0.clone().into_bytes()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn sign_verify_roundtrip_and_tamper_rejection() {
            let kp = SlhKeypair::generate().expect("keygen");
            let payload = [42u8; 32];
            let sig = kp.sign(&payload);
            assert_eq!(sig.len(), SIG_LEN, "128s signatures are 7,856 bytes");

            let pk = SlhPublicKey::from_bytes(&kp.public_key_bytes()).expect("pk parse");
            assert!(pk.verify(&payload, &sig), "honest signature verifies");

            let mut wrong_payload = payload;
            wrong_payload[0] ^= 1;
            assert!(!pk.verify(&wrong_payload, &sig), "payload tamper rejected");

            let mut wrong_sig = sig.clone();
            wrong_sig[100] ^= 1;
            assert!(!pk.verify(&payload, &wrong_sig), "signature tamper rejected");
        }
    }
}
