# 01 · Cryptography

**One sentence:** Everything that can steal or forge money reduces to one assumption — the hash function — and everything else is clearly labeled.

**Requires:** [00-OVERVIEW](00-OVERVIEW.md)

## The rule

Any primitive on the **money path** (theft or forgery) must reduce to hash security. Primitives that only affect **privacy** may use NIST lattice standards, always hybridized with a classical scheme. Nothing anywhere uses pairings, trusted setups, or elliptic-curve assumptions for safety.

Why hashes: Grover's algorithm is the best known quantum attack — a quadratic speedup — so 256-bit hashes keep ~128-bit quantum security. Hash-based cryptography is the conservative extreme of the PQ spectrum; NIST's own fallback if lattices fall.

## The choices

| Job | Primitive | Assumption | Notes |
|---|---|---|---|
| Ownership signatures | **SLH-DSA-128s** (FIPS 205) | hash | 32 B keys, 7,856 B sigs — size is free off-chain; verification is pure hashing (cheap in a STARK). Stateless and misuse-resistant. |
| Issuer / long-lived keys | SLH-DSA-128s | hash | the mint key is the single most valuable quantum target in any asset system |
| Commitments, nullifiers, records | SHA-256, domain-separated | hash | boundary hashes are ALWAYS SHA-256 |
| In-proof hashing | Blake3/Poseidon2-class (performance profile) | hash (newer designs) | profile explicit in every proof; all-SHA conservative profile stays specified |
| Proof system | FRI STARKs | hash | transparent, no setup — see [04-PROOFS](04-PROOFS.md) |
| Note/bundle encryption | **ML-KEM-768 + X25519** hybrid | lattice ∧ ECDH | privacy only; a lattice break leaks privacy, never funds. Hybrid defends harvest-now-decrypt-later today |
| Future option: one-time spends | WOTS+ (~2,144 B) | hash | nullifiers make notes one-spend by construction; requires strict wallet never-re-sign discipline — not v1 |
| Future option: external scriptless swaps | lattice adaptor signatures (LAS lineage) | lattice | amount-bounded interop tier only; never the money path |

## Security claims, precisely

| Property | Assumption | Quantum status |
|---|---|---|
| Theft / forgery | hash | **quantum-safe** (Grover-only) |
| Double-spend / equivocation | hash + Bitcoin ordering | quantum-safe cryptographically; ordering is systemic (below) |
| History validity | hash (FRI, QROM analyses) | quantum-safe (standard caveat) |
| Confidentiality | ML-KEM ∧ X25519 | quantum-safe under lattice assumptions |
| Ordering availability | Bitcoin's economic survival of its own PQ migration (BIP-360/361) | systemic, not cryptographic |

**Terminology policy:** marketing may say **"quantum-safe"** (the ETSI term — and this stack has an unusually strong claim to it); technical writing says **"post-quantum"**; nothing ever says "quantum-proof" — these are well-studied assumptions, not mathematical guarantees.

## Why this can ship before Bitcoin's own migration

PQ signatures are 40–120× bigger than Schnorr — painful on-chain, free off-chain. Ultraviolet keeps signatures and proofs in client-side data, needing from the chain only what a quantum computer cannot forge anyway: hash commitments and proof-of-work ordering. The block-space economics that make L1 migration slow do not apply here.
