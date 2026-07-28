# 00 · Overview

**One sentence:** Ultraviolet is money that works like texting — sent in chat, on Bitcoin within the hour, immune to quantum computers — built from exactly three things, and carried by a messenger that never has to learn it is carrying money.

**Requires:** nothing. Start here.

## The three nouns

1. **Notes** — the money. A note is a hash commitment to `(asset, amount, owner, randomness)`, living only on its owner's devices. Owners are post-quantum hash-based keys. Nobody else ever sees a note. → [02-NOTES](02-NOTES.md)
2. **Records** — the double-spend lock. Spending a note publishes a 64-byte keyless record on Bitcoin; first occurrence wins. Bitcoin orders records and does nothing else — no UTXO is owned, no script is run. → [03-RECORDS](03-RECORDS.md)
3. **Proofs** — the validity. Every hop carries one small STARK proving that transfer: its commitments open, its nullifier derives, value is conserved, and its owner authorized it. A receiver verifies one proof per hop of the note's history, plus a chain lookup per hop to confirm each settled — per-hop checks do not compose, so the whole lineage is checked or nothing is ([04-PROOFS](04-PROOFS.md)).

Everything else is these three composed: payments are notes+records+proofs delivered as chat messages ([05](05-NETWORK.md), [06](06-PAYMENTS.md)), channels are co-signed note-splits ([07](07-CHANNELS.md)), the client is a chat app that moves notes ([08](08-CLIENT.md)). An **optional speed layer** — bonded receipts for sub-second guarantees to strangers — is fully designed but deliberately outside the core: [11-SPEED-LAYER](11-SPEED-LAYER.md).

## The whole system

The protocol is **a client, a messenger, and Bitcoin**. A payment is: message now (instant), visible in seconds (the record hits Bitcoin's mempool), final in ~a block, proven in the background.

The messenger is Signal, and **carrying money costs it no server changes** — it moves a ciphertext it cannot read and a blob it cannot interpret ([05](05-NETWORK.md)). The honest counterweight: Signal blocks third-party clients, so until Signal itself adopts the message type, running the demo means running a Signal server. Earlier drafts claimed *nothing to deploy*; that is no longer true, and [05](05-NETWORK.md) says so at length.

## The one diagram

```
Alice's wallet ──encrypted note bundle──▶ Signal ──mailbox──▶ Bob's wallet
      │                                                        │
      └───────────64-byte record──▶ Bitcoin (OP_RETURN)◀──watches mempool
                     proof ◀── one STARK per hop, follows in background
```

## Locked decisions

| Decision | Value | Owned by |
|---|---|---|
| Assumption base (money path) | hash functions only | [01](01-CRYPTO.md) |
| Signatures (money path) | WOTS+ over Poseidon2, one key per note | [01](01-CRYPTO.md), [02](02-NOTES.md) |
| Encryption | ML-KEM-768 + X25519 hybrid, built (privacy only) | [01](01-CRYPTO.md) |
| Proof system | hand-written AIR on Plonky3, FRI only — never a SNARK wrapper. No zkVM. | [04](04-PROOFS.md) |
| Money-path hash | Poseidon2 over BabyBear, one domain-separated sponge | [01](01-CRYPTO.md) |
| Payment proof format | the *hiding* configuration: amounts stay confidential along a whole lineage | [04](04-PROOFS.md) |
| v1 contract scope | fungible: issue / transfer / burn | [02](02-NOTES.md) |
| Chain role | ordering only; OP_RETURN; no soft fork needed | [03](03-RECORDS.md) |
| Transport | Signal: E2EE messages + attachment CDN | [05](05-NETWORK.md) |
| Server software | no *changes* needed to carry payments; a self-hosted Signal server is needed to demo | [05](05-NETWORK.md), [08](08-CLIENT.md) |
| Durable storage | a separate pluggable role, not the carrier's job | [05](05-NETWORK.md) |
| Client base | fork of Signal (iOS first, AGPL) | [08](08-CLIENT.md) |
| Words | see [GLOSSARY](../GLOSSARY.md); marketing says "quantum-safe", spec says "post-quantum", nobody says "quantum-proof" | [01](01-CRYPTO.md) |

## What exists today

A working core, end to end, with no zkVM anywhere: the money path on Poseidon2, one
STARK per hop proving a complete transfer in **~0.22 s / 208 KB** zero-knowledge
(~0.075 s / 158 KB without hiding), and a wallet that enforces every discipline the
formal models proved necessary. `demo/local2.sh` runs issuance, a validated two-hop
payment, a double-spend the sign-log replays instead of re-signing, and reorg
reconciliation — self-checking, in CI. Eight Quint models cover the protocol and its
wallet/index adapters. One ancestry invariant is inductive for every transition length
in a fixed five-note universe; the assurance matrix labels the remaining results as
bounded checks or counterexamples rather than calling the whole system verified.

Design-stage: the client, the channel dispute state machine, the optional speed layer. **No
professional review of the circuit code yet**, which consensus circuits need before they
hold value. Single authoritative list of everything unfinished:
[99-OPEN-PROBLEMS](99-OPEN-PROBLEMS.md).

## Reading rule

Files only ever reference files with **lower numbers** (and 99). If you understand file N, files > N add to it — nothing doubles back. File [11](11-SPEED-LAYER.md) is optional in the same sense its subject is.
