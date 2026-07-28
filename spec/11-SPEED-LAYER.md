# 11 · Speed Layer (OPTIONAL)

**One sentence:** An optional market of bonded notaries can compress a payment's guarantee from ~1 block to under a second — designed, shelved, and deliberately outside the core protocol.

**Requires:** [05-NETWORK](05-NETWORK.md), [06-PAYMENTS](06-PAYMENTS.md). **Status: not part of v1.** Nothing in the core references this file.

## Why it's optional

The core already gives every payment three signals: the message is instant, the record is visible in seconds (Bitcoin's mempool, watchable by the receiver's client — the same practical assurance as historical 0-conf), and finality lands in ~a block. Channels ([07](07-CHANNELS.md)) give true instant-trustless to ongoing relationships. The only unserved customer is *sub-second guarantees between strangers* — merchants handing goods to unknown parties at scale. If that market materializes, this layer serves it **without changing the protocol**; if it doesn't, this file stays shelved.

## The design (complete, awaiting demand)

**Receipts.** A notary signs `receipt = Sign(nf ‖ H(bundle) ‖ epoch ‖ "will never sign a conflict")` — a portable, bonded, instant guarantee. **Portability is now the open question:** a receipt is only worth carrying if a third party can fetch and check it, and the core no longer assumes a public bulletin board ([05](05-NETWORK.md)). This layer would need the durable blob store, or its own publication path — one more reason it stays shelved.

**Bonds are notes.** A notary's bond is an ordinary note whose spend condition also accepts **a valid fraud proof against that notary** — two conflicting receipts for one nullifier — as the witness. Slashing is just a transfer: the victim spends the cheater's bond with the conflict as the key. No court, no new trust layer. (Prior art: SuperScalar's revealed-secret poison — the cheater's own stake funds the penalty; see [10-COMPARISONS](10-COMPARISONS.md).)

**Two programs, not two networks.** A *notary* (signs receipts, stakes a bond) and a *batcher* (standing checkpoint service with an availability duty) are small programs any operator runs — ordinary clients with jobs, requiring no change to the messaging carrier. Blob-host and infrastructure operators are natural hosts (uptime, billing, colocation), never required ones.

**Payments gain a state:** *guaranteed* (receipt-backed, <1 s) between *visible* and *final*. Wallets choose by amount. A federated middle tier (quorum receipts over a BFT-sequenced log) is a further extension, further shelved.

## The review gate this layer owns

Checkpoint reservations create a race between the sequenced log and direct L1 publication. The reconciliation sketch (reservation beats direct within an epoch; direct wins for nullifiers absent from every log; censorship-exits safe after one clean epoch) **must pass adversarial review before this layer ships** — it is the one place the fast path would touch validation semantics. The core protocol, having exactly one publication path, does not have this problem.

## What building it would take

Receipt, conflict-detection, and fraud-proof types existed in the pre-rewrite kernel and were deleted with it; this layer is design-only and would rebuild them on the current money path. Remaining: the two programs (~small Rust services), bond-sizing policy, a receipt publication and fetch path, and the review above.
