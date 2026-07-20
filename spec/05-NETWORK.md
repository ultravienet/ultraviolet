# 05 · Network: Ordinary Nostr

**One sentence:** Ultraviolet's network is today's Nostr, unmodified — relays store and deliver encrypted payloads they cannot read, and no new server software exists in the core protocol.

**Requires:** [04-PROOFS](04-PROOFS.md)

## Zero new infrastructure

Nostr relays are content-agnostic: they store and forward event kinds they have never seen. So records, address records, and payment bundles ride the existing network unchanged. The core needs exactly two things from the network, both of which Nostr already does:

| Job | Who | Mechanism |
|---|---|---|
| **Storage** — encrypted notes, recovery | vanilla relays + **Blossom** blob servers | relay events for pointers; blobs for proof bundles (~60–320 KB is blob-sized); seed + relays = full recovery |
| **Mailbox** — deliver to offline receivers | vanilla relays | gift-wrapped events (NIP-17/59); store-and-forward is what relays do |

Record publication is client-side ([03](03-RECORDS.md)): self-publish, receiver-publish, or cooperative batching. There is no batcher service, no notary, no bond, and no receipt in the core — the designed **speed layer** that adds sub-second bonded guarantees is optional and lives in [11-SPEED-LAYER](11-SPEED-LAYER.md).

## Why this is safe

Infrastructure can never steal: validity lives in client-side proofs behind PQ signatures, and double-spend ordering lives on Bitcoin. A relay's worst behaviors are losing data (mitigated by replication — publish to several) and censorship (mitigated by using any other relay, or none: every payload can travel any channel, and records go straight to Bitcoin).

## Privacy on a public archive

Payment payloads always wear the ML-KEM(+X25519) envelope regardless of carrier — Nostr relays are public archives, so harvest-now-decrypt-later pressure is *higher* here than on private channels, and NIP-44's native ECDH is classical. The envelope is non-negotiable even relay-to-relay.

## Identity

Social identity is the classical npub; **money answers only to PQ-signed address records** ([02](02-NOTES.md)) carried as events. The carrier is a bulletin board, never an authority — a quantum-forged npub can deface a profile, not redirect a payment.
