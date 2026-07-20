# 00 · Overview

**One sentence:** Ultraviolet is money that works like texting — sent in chat, on Bitcoin within the hour, immune to quantum computers — built from exactly three things, with zero new server software.

**Requires:** nothing. Start here.

## The three nouns

1. **Notes** — the money. A note is a hash commitment to `(asset, amount, owner, randomness)`, living only on its owner's devices. Owners are post-quantum hash-based keys. Nobody else ever sees a note. → [02-NOTES](02-NOTES.md)
2. **Records** — the double-spend lock. Spending a note publishes a 64-byte keyless record on Bitcoin; first occurrence wins. Bitcoin orders records and does nothing else — no UTXO is owned, no script is run. → [03-RECORDS](03-RECORDS.md)
3. **Proofs** — the validity. Every transfer carries one recursive STARK proving its *entire* history. Receiving means verifying one constant-size proof, no matter how old the asset is. → [04-PROOFS](04-PROOFS.md)

Everything else is these three composed: payments are notes+records+proofs delivered over ordinary Nostr ([05](05-NETWORK.md), [06](06-PAYMENTS.md)), channels are co-signed note-splits ([07](07-CHANNELS.md)), the client is a chat app that moves notes ([08](08-CLIENT.md)). An **optional speed layer** — bonded receipts for sub-second guarantees to strangers — is fully designed but deliberately outside the core: [11-SPEED-LAYER](11-SPEED-LAYER.md).

## The whole system

The protocol is **a client, Nostr, and Bitcoin**. No new relays, no new server programs, nothing to deploy. A payment is: message now (Nostr), visible in seconds (the record hits Bitcoin's mempool), final in ~a block, proven in the background.

## The one diagram

```
Alice's wallet ──encrypted note bundle──▶ relay ──mailbox──▶ Bob's wallet
      │                                                        │
      └───────────64-byte record──▶ Bitcoin (OP_RETURN)◀──watches mempool
                     proof ◀── recursive STARK, follows in background
```

## Locked decisions

| Decision | Value | Owned by |
|---|---|---|
| Assumption base (money path) | hash functions only | [01](01-CRYPTO.md) |
| Signatures | SLH-DSA-128s | [01](01-CRYPTO.md) |
| Encryption | ML-KEM-768 + X25519 hybrid (privacy only) | [01](01-CRYPTO.md) |
| zkVM | SP1, raw STARK only — never a SNARK wrapper | [04](04-PROOFS.md) |
| v1 contract scope | fungible: issue / transfer / burn | [02](02-NOTES.md) |
| Chain role | ordering only; OP_RETURN; no soft fork needed | [03](03-RECORDS.md) |
| Transport | today's Nostr relays + Blossom blobs, unmodified | [05](05-NETWORK.md) |
| Server software | none in core; speed layer optional | [05](05-NETWORK.md), [11](11-SPEED-LAYER.md) |
| Client base | fork of White Noise (audited Rust, MLS) | [08](08-CLIENT.md) |
| Words | see [GLOSSARY](../GLOSSARY.md); marketing says "quantum-safe", spec says "post-quantum", nobody says "quantum-proof" | [01](01-CRYPTO.md) |

## What exists today

Working kernel + prover (27 tests): real SLH-DSA spends, two-hop recursive proofs — one 1,242 KB proof verifies any history depth, measured 2026-07-22 on a laptop. Design-stage: client, channel dispute/settlement state machine, the optional speed layer. Single authoritative list of everything unfinished: [99-OPEN-PROBLEMS](99-OPEN-PROBLEMS.md).

## Reading rule

Files only ever reference files with **lower numbers** (and 99). If you understand file N, files > N add to it — nothing doubles back. File [11](11-SPEED-LAYER.md) is optional in the same sense its subject is.
