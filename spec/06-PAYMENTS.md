# 06 · Payments (Darknoise)

**One sentence:** The default payment is a message now, visible on Bitcoin in seconds, final in a block — and it deletes liquidity as a concept; Lightning survives only as a hash-shaped door.

**Requires:** [05-NETWORK](05-NETWORK.md)

## The default payment: Alice pays Bob $20 in a chat

| | What happens | Latency |
|---|---|---|
| **Send** | wallet selects notes, derives nullifiers, encrypts the bundle to Bob's scan key, ships to mailbox, publishes the record ([03](03-RECORDS.md)) | ~0 s |
| **Visible** | the $20 bubble appears (Nostr is instant); the record hits Bitcoin's mempool, which Bob's client watches — the practical assurance that ran a decade of 0-conf retail. Bob asleep? It waits. Receivers need zero liveness, zero setup, zero bitcoin | seconds |
| **Proven** | the STARK follows asynchronously (~1 min laptop, seconds delegated); Bob verifies in ms | minutes, background |
| **Final** | the record confirms; assurance upgrades to proof-of-work automatically | ~1 block |

What Lightning charges for its instant finality, all deleted here: inbound liquidity, channel opens, splicing, force-close risk, user watchtowers, LSP mediation. Direct transfers aren't routed, so liquidity doesn't exist as a concept. Honest line item: between mempool and confirmation the assurance is practical, not cryptographic — fine for $20 among humans; "wait one block" for $2M; **channels ([07](07-CHANNELS.md)) for instant-trustless with regulars; an optional bonded-receipt layer ([11](11-SPEED-LAYER.md)) exists on paper for sub-second guarantees to strangers, if that market ever demands it.**

Streaming/micropayments: channel updates ([07](07-CHANNELS.md)) — machine-speed, bilateral, free per beat.

## Hash-locked notes: conditional payments and the Lightning door

A note whose owner is a **hash-lock condition** (`kernel/src/hashlock.rs`) is spendable by revealing the SHA-256 preimage of `payment_hash`, or by the refund key after `timeout_epoch`. Pure hashes, PQ by construction — and preimage-compatible with today's Lightning HTLCs.

**Gateway swap (pay any LN invoice, atomically, no channels of ours):**

```
Alice locks a note to the invoice's payment_hash, timeout T
Gateway pays the invoice on Lightning
LN settlement reveals preimage p  →  p IS the gateway's claim key for the note
Gateway never pays → timeout refunds Alice
```

Reverse swaps receive from LN symmetrically. Gateways are a competitive RFQ market — custody-free, exposure bounded per swap, classical only on Lightning's side of the door. **Watch item:** this rides on LN staying HTLC/SHA-256; a PTLC migration there would need new gateway plumbing (ours is unchanged).

## The four rails

| Rail | Finality | For |
|---|---|---|
| **Darknoise direct** | visible in seconds → final ~1 block | **the default** — anyone to anyone |
| Channel ([07](07-CHANNELS.md)) | instant & bilateral; assumes liveness (weakest tier) | ongoing relationships, machine-speed streaming |
| Gateway (above) | atomic per swap | reach into Lightning's economy |
| Speed layer ([11](11-SPEED-LAYER.md), optional) | guaranteed <1 s, bonded | stranger retail — built only if demanded |
