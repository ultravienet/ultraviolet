# 03 · Records & Bitcoin

**One sentence:** Spending a note publishes a keyless 64-byte record on Bitcoin, first occurrence wins, and that is the chain's entire job.

**Requires:** [02-NOTES](02-NOTES.md)

## The record

```
nf     = H(nullifier_key ‖ note_commitment)   — deterministic per note
record = nf ‖ H(transfer_bundle)              — 64 bytes, in OP_RETURN
```

Consensus rule (enforced client-side, `kernel2/src/nullifier.rs`): **a spend of note N is valid iff the first on-chain occurrence of nf(N) carries this transfer's bundle hash.** Two conflicting spends produce the same `nf`; at most one is first; the bundle hash pins which transfer won. Double-spend prevention and equivocation resistance with zero on-chain verification — and nothing on-chain for a quantum computer to attack.

## Publication — no service required

Records are **keyless**: anyone can publish anyone's record, and copying one just pays the fee for it. Three publication modes, all client-side:

- **Self-publish (default):** the sender's client posts its own 64-byte record in OP_RETURN. Needs a few hundred sats and any way to broadcast a transaction.
- **Receiver-publish:** an asset-only sender with no sats hands the record to the receiver, who publishes it — the receiver is the party who wants it on-chain anyway.
- **Cooperative batching:** any client publishing anyway may carry neighbors' records under one 32-byte Merkle root, amortizing fees. Trade: the batch's contents must stay retrievable for first-occurrence scanning — a *durable storage* duty the messaging carrier does not perform ([05](05-NETWORK.md)), so batching needs a blob host that plain transfers do not. Inline is the conservative floor.

First-occurrence order is fully deterministic: `(block height, transaction index, leaf index within a batch)`. A standing batching *service* is part of the optional speed layer ([11](11-SPEED-LAYER.md)), not the core.

## What this does to Bitcoin

OP_RETURN outputs never enter the UTXO set: millions of transfers add **zero** entries to node state — that claim stands and is the important one.

**Corrected block-space numbers (audit #13 E1, measured from the signet transactions):** the 64-byte payload is *non-witness* data, so it weighs ×4. The OP_RETURN output alone is **300 WU** (66-byte script → 75-byte output), and a whole record transaction — one taproot input, the OP_RETURN, one change output — measured **143–186 vB (572–744 WU)**. That is *comparable to an ordinary payment*, not denser. An earlier version of this file claimed "~64 weight units per transfer … ~10× settlement density," which was wrong: it counted the payload bytes only, ignored the ×4 non-witness factor, and ignored the input and change output the transaction needs.

Density comes from **batching**, not from a single record: one 32-byte Merkle root is a 34-byte script → 43-byte output → **172 WU total**, amortized across every payment in the batch (≈1.7 WU per payment at N=100). Un-batched, Ultraviolet's on-chain cost per payment is roughly one ordinary transaction; the wins are zero UTXO-set growth, prunability, and privacy. No soft fork, no new opcodes; when Bitcoin's own PQ migration (BIP-360/361) lands, nothing here changes — Ultraviolet consumes ordering, not script. A quantum thief who steals the Bitcoin UTXO that *carried* a record steals nothing.

### Datacarrier invariant

A record's data is **64 bytes** — scriptPubKey `OP_RETURN ‖ push ‖ 64B` = 66 bytes, under the historical **83-byte** OP_RETURN datacarrier limit. Ultraviolet uses **no data-bearing spendable outputs** and stores **nothing in the Taproot witness**. This is a deliberate invariant, not a coincidence: it keeps records relayable under the strictest datacarrier policy Bitcoin has plausibly proposed (e.g. BIP-110, which reinstates the 83-byte limit and caps other data outputs at 34 bytes — see [99](99-OPEN-PROBLEMS.md)). If policy ever tightened *below* 64 bytes, **batched** publication is the fallback: N records collapse to one **32-byte** Merkle root, which fits even a 34-byte cap. Ultraviolet is the minimal, monetary, prunable case such policies aim to protect — not the bloat they target.

## Epochs

Record time is measured in **epochs** — fixed spans of Bitcoin blocks (v1: 6 blocks ≈ 1 hour). Epochs are the protocol's clock for hash-lock timeouts ([06](06-PAYMENTS.md)) and channel dispute windows ([07](07-CHANNELS.md)). The core has exactly one publication path — direct on-chain, first occurrence wins in deterministic chain order — so **there is no priority rule to reason about**. (The optional speed layer, [11](11-SPEED-LAYER.md), introduces a second path and owns the reconciliation problem that comes with it.)

## The ancestry rule (normative)

First occurrence decides which spend of a note is real. The rule that was missing — and whose
absence was the bug, not any line of code — is that a receiver must apply it to **every hop in a
note's history, not only their own**.

A receiver MUST, before accepting a note:

1. **Bind the ancestry to the proof.** The sender supplies the ancestry, so it is adversarial
   input. Fold each hop's canonical transition bytes from `GENESIS_DIGEST` and require the result to
   equal the `history_digest` the *verified proof* committed to. Do this **before any chain lookup**:
   a receiver that probes records first leaks which nullifiers it was willing to ask about.
2. **Check every hop settled.** For each hop after genesis, every nullifier it spends MUST have a
   first occurrence whose bundle hash is that hop's. Hop 0 is genesis and is exempt — issuance
   publishes no record, and its validity is the in-circuit genesis authorization. That exemption is
   safe because it is *positional*, and position is pinned by the digest chain.
3. **Derive, never accept, a hop's nullifiers.** Records are keyless, so anyone may publish
   `(nf, bundle_hash)` for any pair. A hop that carried a nullifier field alongside its bytes could
   be forged: publish `(fresh_nf, H(losing bytes))` and pair the two. Nullifiers come out of the
   canonical encoding or the hop is refused.

**Why per-hop checking does not suffice.** The tempting induction — *my sender checked their own
hop, so their note is good* — fails exactly when the sender is the adversary, and you cannot verify
that somebody else ran a check. An attacker routes a losing branch through a second wallet of their
own, whose only misbehaviour is skipping a check nobody can observe, and two conforming receivers
each accept. One note becomes two. Found by `formal/multihop.qnt`, tracked as
[issue #14](https://github.com/ultravienet/ultraviolet/issues/14), implemented in
`wallet2/src/accept.rs`.

**What this costs, stated plainly.** One chain lookup per ancestor hop, and ~136 bytes per hop on
the wire (`40 + 32×(n_nullifiers + n_outputs)`, not the 64-byte record). So receiving is O(1) in
*proof verification* and **O(n) in chain lookups** — and the chain-view provider learns every
nullifier in the note's history, a leak that grows with a coin's age. Both costs exist because
settlement is checked *outside* the proof; moving it inside is the open work ([99](99-OPEN-PROBLEMS.md)).

## Threat: front-running a record (audit #13 B1)

Records are keyless by design — anyone may publish anyone's. That yields a griefing vector: a mempool watcher sees a revealed `nf`, pairs it with a **garbage** bundle hash, and out-fees the honest record. If the attacker's confirms first, first-occurrence binds `nf` to a bundle nobody can produce, and the note is stuck for everyone.

What it is and isn't:

- **Not theft.** Since spend authorization is proven in-circuit ([04](04-PROOFS.md)) and the nullifier is bound to note ownership, an attacker cannot produce a *valid* competing spend — only an unbacked one. They cannot move the value anywhere.
- **Not profitable.** The attacker pays a fee to destroy value they don't receive. The victim's loss is the attacker's cost with no upside — pure vandalism.
- **Copying the honest record verbatim is harmless.** Both fields are public, but re-publishing the same `nf ‖ H(bundle)` is idempotent: the honest payment still validates. Only a *mismatched* pairing grieves.
- **Real residue: the note is bricked.** Neither party can spend it afterwards. There is no recovery in v1.

Direction (not yet implemented): treat only a **backed** occurrence as binding — a record counts once someone can present a valid proof whose bundle hash matches it, so unbacked garbage is inert. That requires receivers to fetch and check competing bundles, which changes the chain-view cost model, so it is specified as future work ([99](99-OPEN-PROBLEMS.md) `[FRONTRUN]`) rather than claimed. **Until then, treat a payment's `nf` as burnable by any observer between broadcast and confirmation.**

## The chain-view check

One check lives outside the proof: that no *earlier* occurrence of `nf` exists. Absence can't be proven by inclusion, so the receiver checks a Bitcoin view.

**Correction (audit #13 B2):** an earlier version of this file claimed a dishonest index "can make a valid transfer look invalid, never the reverse." That is **wrong** for a first-occurrence rule. An index that *omits* an earlier conflicting record makes a double-spend look valid — so the chain view is trusted for **completeness**, not just availability, and a receiver's own node is the only safe source. The same failure comes from starting a scan too late (a mis-set `UV_BTC_SCAN_FROM`): define a minimum scan start per asset and fail closed on incomplete history ([99](99-OPEN-PROBLEMS.md) `[SCAN-FLOOR]`).
