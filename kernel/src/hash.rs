//! Boundary-hash abstraction.
//!
//! Protocol boundaries — note commitments, nullifiers, on-chain records,
//! signing payloads — are ALWAYS SHA-256, regardless of feature flags: these
//! values are consensus-critical and long-lived. The `perf-hash` feature
//! selects BLAKE3 only for `circuit_hash`, the profile used inside FRI
//! recursion where proving speed matters and the performance profile of
//! spec/01-CRYPTO.md applies.

use sha2::{Digest, Sha256};

/// A 32-byte hash output.
pub type Hash256 = [u8; 32];

/// Domain-separated SHA-256 over the concatenation of `parts`.
///
/// Every boundary hash carries an explicit domain tag so no two protocol
/// contexts can ever collide on the same preimage.
pub fn boundary_hash(domain: &str, parts: &[&[u8]]) -> Hash256 {
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

/// Plain SHA-256 (no domain framing). Used where an external convention
/// fixes the digest — e.g. SP1's public-values digest, which is exactly
/// `sha256(committed_bytes)`.
pub fn sha256(bytes: &[u8]) -> Hash256 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The in-recursion hash for the active profile.
///
/// Performance profile (`perf-hash` feature): BLAKE3.
/// Conservative profile (default): SHA-256.
pub fn circuit_hash(domain: &str, parts: &[&[u8]]) -> Hash256 {
    #[cfg(feature = "perf-hash")]
    {
        let mut h = blake3::Hasher::new();
        h.update(&(domain.len() as u64).to_le_bytes());
        h.update(domain.as_bytes());
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        *h.finalize().as_bytes()
    }
    #[cfg(not(feature = "perf-hash"))]
    {
        boundary_hash(domain, parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation() {
        let a = boundary_hash("uv/a/v1", &[b"payload"]);
        let b = boundary_hash("uv/b/v1", &[b"payload"]);
        assert_ne!(a, b, "distinct domains must never collide");
    }

    #[test]
    fn length_framing_prevents_ambiguity() {
        // ("ab", "c") must not hash equal to ("a", "bc").
        let a = boundary_hash("uv/t/v1", &[b"ab", b"c"]);
        let b = boundary_hash("uv/t/v1", &[b"a", b"bc"]);
        assert_ne!(a, b, "length framing must disambiguate part boundaries");
    }
}
