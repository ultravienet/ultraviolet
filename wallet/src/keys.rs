//! A wallet identity: everything derived deterministically from one 32-byte
//! master seed, so the only thing persisted is the seed.
//!
//! - SLH-DSA-128s spend keypair (owns notes, signs spends and address records)
//! - ML-KEM-768 + X25519 scan keypair (receives encrypted payments)
//! - a nullifier secret (makes this identity's nullifiers deterministic + private)

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ultraviolet_kernel::address::AddressRecord;
use ultraviolet_kernel::hash::{boundary_hash, Hash256};
use ultraviolet_kernel::sig::slh::SlhKeypair;

use crate::envelope::{generate_scan_from, ScanPublic, ScanSecret};

const OWNER_KEY_DOMAIN: &str = "uv/owner-key/v1";

fn sub_seed(master: &[u8; 32], domain: &str) -> [u8; 32] {
    boundary_hash(domain, &[master])
}

pub struct Identity {
    master: [u8; 32],
    slh: SlhKeypair,
    scan_secret: ScanSecret,
    scan_public: ScanPublic,
    nullifier_secret: Hash256,
}

impl Identity {
    /// Reconstruct an identity from its master seed. Deterministic: the same
    /// seed always yields the same keys.
    pub fn from_seed(master: [u8; 32]) -> Self {
        let mut slh_rng = ChaCha20Rng::from_seed(sub_seed(&master, "uv/kdf/slh/v1"));
        let slh = SlhKeypair::generate_with_rng(&mut slh_rng).expect("slh keygen");

        let mut scan_rng = ChaCha20Rng::from_seed(sub_seed(&master, "uv/kdf/scan/v1"));
        let (scan_secret, scan_public) = generate_scan_from(&mut scan_rng);

        let nullifier_secret = sub_seed(&master, "uv/kdf/nf/v1");
        Identity { master, slh, scan_secret, scan_public, nullifier_secret }
    }

    pub fn master_seed(&self) -> [u8; 32] {
        self.master
    }

    /// The hash a note's `owner_key` carries for notes this identity owns.
    pub fn owner_key(&self) -> Hash256 {
        boundary_hash(OWNER_KEY_DOMAIN, &[&self.slh.public_key_bytes()])
    }

    /// The secret used as `nullifier_key` when spending this identity's notes.
    pub fn nullifier_key(&self) -> Hash256 {
        self.nullifier_secret
    }

    pub fn scan_secret(&self) -> &ScanSecret {
        &self.scan_secret
    }

    pub fn slh(&self) -> &SlhKeypair {
        &self.slh
    }

    /// The scan tag others post encrypted bundles under (public, unlinkable to
    /// spend identity beyond what the address already reveals).
    pub fn scan_tag(&self) -> String {
        hex::encode(boundary_hash("uv/scan-tag/v1", &[&self.owner_key()]))
    }

    /// This identity's published, SLH-DSA-signed address record.
    pub fn address_record(&self) -> AddressRecord {
        let mut ar = AddressRecord {
            scan_kem_pk: self.scan_public.to_bytes(),
            spend_root: self.owner_key(),
            prev: [0u8; 32],
            pq_sig: Vec::new(),
        };
        // Deterministic signature → the same identity always prints the same
        // address string (a published address should be stable).
        ar.pq_sig = self.slh.sign_deterministic(&ar.signing_payload());
        ar
    }

    /// Serialize the address record to a shareable `uv1<hex>` string.
    pub fn address_string(&self) -> String {
        let ar = self.address_record();
        let bytes = bincode::serialize(&ar).expect("serialize address");
        format!("uv1{}", hex::encode(bytes))
    }
}

/// Parse an address string back into scan keys and the recipient owner-key
/// (`spend_root`) a sender needs.
pub struct Recipient {
    pub scan_public: ScanPublic,
    pub owner_key: Hash256,
}

pub fn parse_address(s: &str) -> Option<Recipient> {
    let hexpart = s.strip_prefix("uv1")?;
    let bytes = hex::decode(hexpart).ok()?;
    let ar: AddressRecord = bincode::deserialize(&bytes).ok()?;
    let scan_public = ScanPublic::from_bytes(&ar.scan_kem_pk).ok()?;
    Some(Recipient { scan_public, owner_key: ar.spend_root })
}

/// The scan tag a sender files a bundle under, given a recipient owner-key.
pub fn scan_tag_for(owner_key: &Hash256) -> String {
    hex::encode(boundary_hash("uv/scan-tag/v1", &[owner_key]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic_from_seed() {
        let seed = [42u8; 32];
        let a = Identity::from_seed(seed);
        let b = Identity::from_seed(seed);
        assert_eq!(a.owner_key(), b.owner_key());
        assert_eq!(a.nullifier_key(), b.nullifier_key());
        assert_eq!(a.address_string(), b.address_string());

        let c = Identity::from_seed([7u8; 32]);
        assert_ne!(a.owner_key(), c.owner_key());
    }

    #[test]
    fn address_roundtrips_and_signature_verifies() {
        use ultraviolet_kernel::sig::Verifier;
        let id = Identity::from_seed([9u8; 32]);
        let ar = id.address_record();
        assert!(id.slh().public_key().verify(&ar.signing_payload(), &ar.pq_sig));

        let r = parse_address(&id.address_string()).unwrap();
        assert_eq!(r.owner_key, id.owner_key());
        assert_eq!(scan_tag_for(&r.owner_key), id.scan_tag());
    }
}
