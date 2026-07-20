# 04 · Proofs & Recursion

**One sentence:** Every transfer carries one constant-size recursive STARK proving its entire history, so receiving is O(1) forever — measured, not promised.

**Requires:** [03-RECORDS](03-RECORDS.md)

## Proof-carrying data

Each hop's proof verifies the previous hop's proof *inside the circuit* (`guest/src/main.rs`), then checks: the spend signatures, value conservation, correct nullifier derivation, linkage (this transfer spends only notes the previous hop created), and advances a running history digest. A receiver verifies exactly one proof regardless of depth. Public values expose only nullifiers, output commitments, and the contract id — amounts, owners, and history stay in the witness, hidden even from the receiver.

## The stack (locked)

**SP1 zkVM, raw STARK output only — never its SNARK wrapper** (pairings would reintroduce a trusted setup and break the PQ claim). The kernel's transition function (`kernel/src/transfer.rs`, `kernel/src/history.rs`) runs identically on the host and in the guest; contracts are plain Rust. FRI soundness is hash-based; profile per [01-CRYPTO](01-CRYPTO.md).

## Measured (laptop CPU, SP1 v6.3, July 2026)

| Mode | Prove | Size |
|---|---|---|
| Core | ~14 s / hop | 2,714 KB |
| **Compressed (recursion-ready)** | ~55–71 s / hop | **1,242 KB — constant across depth** |

Verification: milliseconds. The historical 50–300 KB figure is a target under tighter FRI parameters, not a measurement. GPU and delegated proving shrink wall-clock, not size; a delegated prover never holds spend keys (it does see the notes it proves).

## Status

Two-hop recursion demonstrated end-to-end 2026-07-22, including in-circuit rejection of linkage violations. In-circuit SLH-DSA verification and channel disputes are the next guest milestones ([99](99-OPEN-PROBLEMS.md)).
