# 03 · Records & Bitcoin

**One sentence:** Spending a note publishes a keyless 64-byte record on Bitcoin, first occurrence wins, and that is the chain's entire job.

**Requires:** [02-NOTES](02-NOTES.md)

## The record

```
nf     = H(nullifier_key ‖ note_commitment)   — deterministic per note
record = nf ‖ H(transfer_bundle)              — 64 bytes, in OP_RETURN
```

Consensus rule (enforced client-side, `kernel/src/nullifier.rs`): **a spend of note N is valid iff the first on-chain occurrence of nf(N) carries this transfer's bundle hash.** Two conflicting spends produce the same `nf`; at most one is first; the bundle hash pins which transfer won. Double-spend prevention and equivocation resistance with zero on-chain verification — and nothing on-chain for a quantum computer to attack.

## Publication — no service required

Records are **keyless**: anyone can publish anyone's record, and copying one just pays the fee for it. Three publication modes, all client-side:

- **Self-publish (default):** the sender's client posts its own 64-byte record in OP_RETURN. Needs a few hundred sats and any way to broadcast a transaction.
- **Receiver-publish:** an asset-only sender with no sats hands the record to the receiver, who publishes it — the receiver is the party who wants it on-chain anyway.
- **Cooperative batching:** any client publishing anyway may carry neighbors' records under one 32-byte Merkle root, amortizing fees. Trade: the batch's contents must stay retrievable for first-occurrence scanning. Inline is the conservative floor.

First-occurrence order is fully deterministic: `(block height, transaction index, leaf index within a batch)`. A standing batching *service* is part of the optional speed layer ([11](11-SPEED-LAYER.md)), not the core.

## What this does to Bitcoin

OP_RETURN outputs never enter the UTXO set: millions of transfers add **zero** entries to node state. ~64 weight units per transfer vs ~560 for a typical transaction — ~10× settlement density before batching. No soft fork, no new opcodes; when Bitcoin's own PQ migration (BIP-360/361) lands, nothing here changes — Ultraviolet consumes ordering, not script. A quantum thief who steals the Bitcoin UTXO that *carried* a record steals nothing.

## Epochs

Record time is measured in **epochs** — fixed spans of Bitcoin blocks (v1: 6 blocks ≈ 1 hour). Epochs are the protocol's clock for hash-lock timeouts ([06](06-PAYMENTS.md)) and channel dispute windows ([07](07-CHANNELS.md)). The core has exactly one publication path — direct on-chain, first occurrence wins in deterministic chain order — so **there is no priority rule to reason about**. (The optional speed layer, [11](11-SPEED-LAYER.md), introduces a second path and owns the reconciliation problem that comes with it.)

## The chain-view check

One check lives outside the proof: that no *earlier* occurrence of `nf` exists. Absence can't be proven by inclusion; the receiver checks a Bitcoin view (own node, or any index trusted for availability only — a lying index can make a valid transfer look invalid, never the reverse).
