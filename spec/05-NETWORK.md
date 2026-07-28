# 05 · Network: Signal

**One sentence:** Ultraviolet's carrier is Signal — payments ride the existing end-to-end-encrypted session as ordinary message content, the server sees only a ciphertext envelope and an opaque blob, and **no server-side change is required to carry money**.

**Requires:** [04-PROOFS](04-PROOFS.md)

## What the carrier has to do

The core needs exactly two things from a network, and Signal does both already:

| Job | Mechanism |
|---|---|
| **Mailbox** — deliver to offline receivers | Signal's store-and-forward queue. Receivers need zero liveness; the payment waits for them. |
| **Bulk transfer** — move the proof bundle | Signal's **attachment CDN**: encrypted blobs, tens of MB, first-class. Our bundles — ~208 KB per hop of a coin's history, so ~1 MB at five hops and ~20 MB at a hundred — are unremarkable to it. |

Record publication is separate and client-side ([03](03-RECORDS.md)): self-publish, receiver-publish, or cooperative batching, straight to Bitcoin. There is no batcher service, no notary, no bond, and no receipt in the core — the designed **speed layer** is optional and lives in [11-SPEED-LAYER](11-SPEED-LAYER.md).

## Why Signal, concretely

Three things fall out that a public-relay carrier could not give us:

- **The bundle fits.** Attachments are designed for megabyte payloads. On an event-based bulletin board the bundle exceeded ordinary size limits and had to be split to a separate blob host — an availability dependency, an extra service, and a live [99](99-OPEN-PROBLEMS.md) item. On Signal that problem does not exist. (The figure that made this acute was the zkVM's 1.2 MB proof; a hop is ~208 KB now, so a bundle is ~208 KB per hop of history.)
- **The payment graph doesn't leak.** Sealed sender means the server does not learn who sent a message. There is no public archive to scrape, and no tag under which a stranger who knows your address can enumerate and time your payments. On the previous carrier that enumeration was possible and real.
- **Harvest-now-decrypt-later is bounded.** Signal delivers and deletes rather than archiving publicly, and its own transport is already post-quantum (PQXDH, then the ratchet). Our ML-KEM(+X25519) envelope stays mandatory regardless — payloads must not depend on carrier crypto — but the carrier is no longer working against us.

**The server change required for payments is none.** Signal's server handles a ciphertext envelope it cannot read and an attachment blob it cannot interpret. A payment is a field inside the encrypted message. That is the whole integration surface, and it means adopting this costs a messenger operator no new trust, no new data, and no new liability.

## What Signal does not provide

Two honest losses. Neither is fatal; both are load-bearing enough to state plainly.

**1. You have to run a server, until you don't.** Signal does not federate and blocks third-party clients from its production network, so a working implementation runs against **your own deployment** of the Signal server ([08](08-CLIENT.md)). This is a real reversal: earlier drafts of this protocol claimed *zero new server software, nothing to deploy*, and that claim is now false. It becomes true again only if Signal itself adopts the message type — which is a business conversation, not an engineering one. Until then, operating a server is the entry price, and it is worth naming that this makes the network **permissioned**: the carrier can decline.

**2. No durable public storage.** Signal delivers then deletes. That is exactly right for payments and exactly wrong for three duties a public blob store was quietly carrying:

| Duty | Where | Why delivery-then-delete breaks it |
|---|---|---|
| Channel state retrievability | [07](07-CHANNELS.md) | Settlement presents the highest seq **backed by a retrievable co-signed state**. If the state isn't fetchable at dispute time, that claim drops — an availability failure becomes a theft vector. |
| Cooperative-batch contents | [03](03-RECORDS.md) | A batch commits to a 32-byte root; scanning for first occurrence needs the contents to stay fetchable. |
| Portable receipts | [11](11-SPEED-LAYER.md) | A bonded receipt is only worth carrying if a third party can fetch and check it. |

So **durable storage is its own role in this design, not a property of the carrier**: any HTTP blob host, replicated at the holder's discretion, addressed by content hash. Splitting it out is better architecture than the bundling it replaces — transport and storage were always different duties with different trust models — but it *is* a new component, and the base payment rail is deliberately built not to need it: a plain transfer requires delivery only.

## Privacy

Payment payloads always wear the ML-KEM(+X25519) envelope regardless of carrier — the money path never inherits its confidentiality from the transport. What Signal adds on top is metadata protection (sealed sender, no public archive) that the payload envelope cannot provide by itself.

## Identity

Money answers only to PQ-signed address records ([02](02-NOTES.md)), and those are carrier-agnostic — the address layer verifies the hash-based chain and treats whatever moved the bytes as a courier. In practice the two parties exchange address records **in-band on first contact**, which needs no profile change, no directory, and no server change. A compromised or quantum-forged carrier account can impersonate a contact socially; it cannot redirect a payment, because the payment target is the PQ chain and not the account.

The cost of in-band exchange is that you cannot look up a stranger you have never talked to. For a chat-first payment app that is close to free — you pay people you are in a conversation with — but it does mean address discovery is no longer a public lookup.
