# 01 · Cryptography

**One sentence:** Everything that can steal or forge money reduces to one assumption — the hash function — and everything else is clearly labeled.

**Requires:** [00-OVERVIEW](00-OVERVIEW.md)

## The rule

Any primitive on the **money path** (theft or forgery) must reduce to hash security. Primitives that only affect **privacy** may use NIST lattice standards, always hybridized with a classical scheme. Nothing anywhere uses pairings, trusted setups, or elliptic-curve assumptions for safety.

Why hashes: Grover's algorithm is the best known quantum attack — a quadratic speedup — so 256-bit hashes keep ~128-bit quantum security. Hash-based cryptography is the conservative extreme of the PQ spectrum; NIST's own fallback if lattices fall.

## The choices

| Job | Primitive | Assumption | Notes |
|---|---|---|---|
| Note spend authorization | **WOTS+ over Poseidon2**, one key per note | hash | a note is spent once, so reusability is waste: 67 chains of ≤15 permutations, verified in-circuit at one row per hash. **Signing twice with one key reveals it** — hence per-note keys and the wallet's replay discipline ([02](02-NOTES.md)) |
| Issuer / long-lived keys | SLH-DSA-128s (FIPS 205) | hash | reusable by necessity; the mint key is the single most valuable quantum target in any asset system, and it signs rarely enough that a hypertree's cost is irrelevant |
| Commitments, nullifiers, records, history | **Poseidon2 over BabyBear**, one domain-separated sponge | hash | the proof system's own hash, so a money-path hash is one AIR row. Every use is the same sponge with a different domain tag ([`air/src/sponge.rs`](../air/src/sponge.rs)) |
| Proof system | FRI STARKs, hand-written AIR on Plonky3 | hash | transparent, no setup, **no zkVM and never a SNARK wrapper** — pairings would break the PQ claim. See [04-PROOFS](04-PROOFS.md) |
| Note/bundle encryption | **ML-KEM-768 + X25519** hybrid (`envelope/`, built) | lattice ∧ ECDH | privacy only; a lattice break leaks privacy, never funds. Hybrid defends harvest-now-decrypt-later today, and both legs are load-bearing by test |
| Future option: external scriptless swaps | lattice adaptor signatures (LAS lineage) | lattice | amount-bounded interop tier only; never the money path |

**What changed and why it is not a weakening.** The money path used SLH-DSA signatures
and SHA-256 boundary hashes. Both are excellent; both were the wrong shape for a
hand-written circuit. Measured: verifying SLH-DSA in-circuit was 77% of a payment's
cost, almost all of it hypertree machinery whose only purpose is making a key *reusable*
— which a one-spend note does not need. And SHA-256 costs 1,353 in-circuit cycles
against Poseidon2's 402, because Poseidon2 *is* the proof system's hash. The assumption
base is unchanged: still hashes only, still Grover-quadratic. What moved is which hash,
and how many times it runs.

## Security claims, precisely

| Property | Assumption | Quantum status |
|---|---|---|
| Theft / forgery | hash | **quantum-safe** (Grover-only) |
| Double-spend / equivocation | hash + Bitcoin ordering | quantum-safe cryptographically; ordering is systemic (below) |
| History validity | hash (FRI, QROM analyses) | quantum-safe (standard caveat) |
| Confidentiality | ML-KEM ∧ X25519 | quantum-safe under lattice assumptions |
| Ordering availability | Bitcoin's economic survival of its own PQ migration (BIP-360/361) | systemic, not cryptographic |

### The sponge's capacity, stated deliberately

**DECIDED 2026-07-27: 8 BabyBear lanes of capacity, ≈248 bits, ≈2^124 generic collision cost —
accepted, and below the 128-bit line on purpose.**

Every commitment, nullifier, spend anchor and history digest in the system is an output of the
same domain-separated sponge (`air/src/sponge.rs`), which carries 8 field elements of capacity.
BabyBear elements are just under 31 bits, so the capacity is ~248 bits and generic
collision-finding costs ~2^124 rather than the 2^128 a round number would suggest.

Accepted because 2^124 is not a number anyone reaches — it is beyond the reach of an adversary
who can already perform on the order of 10^37 operations — and because the alternative is real:
more capacity means more absorb rows per hash, a taller trace, and slower proving, possibly past
the 1,024-row boundary that currently lets a whole payment cost the same trace height as a
signature alone.

Recorded here rather than left implicit because it was previously nobody's decision: it fell out
of the sponge's shape, and an audit found it rather than a design note declaring it. If a
reviewer disagrees, this is the paragraph to argue with.

**Terminology policy:** marketing may say **"quantum-safe"** (the ETSI term — and this stack has an unusually strong claim to it); technical writing says **"post-quantum"**; nothing ever says "quantum-proof" — these are well-studied assumptions, not mathematical guarantees.

## Why this can ship before Bitcoin's own migration

PQ signatures are 40–120× bigger than Schnorr — painful on-chain, free off-chain. Ultraviolet keeps signatures and proofs in client-side data, needing from the chain only what a quantum computer cannot forge anyway: hash commitments and proof-of-work ordering. The block-space economics that make L1 migration slow do not apply here.
