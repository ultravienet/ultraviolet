# 02 · Notes & Ownership

**One sentence:** Money is notes — private hash commitments owned by post-quantum keys — and addresses are published bundles of the keys needed to pay someone, never touching a blockchain.

**Requires:** [01-CRYPTO](01-CRYPTO.md)

## Notes

A **note** commits to `(contract_id, value, owner_key, randomness)` under a domain-separated SHA-256 commitment (`kernel/src/note.rs`). Notes exist only in their owner's client-side data; no chain, relay, or third party ever sees one. `randomness` makes commitments unlinkable; `owner_key` is the hash of an SLH-DSA public key — or of a [hash-lock condition](06-PAYMENTS.md), making conditional notes ordinary notes.

**v1 contract scope (locked):** fungible assets — issue, transfer, burn. The kernel interface is written for generality; arbitrary Rust contracts are v2 and change no consensus.

## Spending

A spend is authorized by an SLH-DSA signature over the transfer's bundle hash. A transfer consumes input notes and creates output notes; value is conserved under checked arithmetic — an overflowing sum is invalid, never wrapped (`kernel/src/transfer.rs`). What makes a spend *final* is the record layer ([03](03-RECORDS.md)); what makes it *valid* is the proof layer ([04](04-PROOFS.md)).

## Addresses: non-interactive, PQ

An address is `(spend_root, scan_kem_pk)` — a spend-key root plus an ML-KEM-768(+X25519) encapsulation key. Senders encapsulate to the scan key, derive the note's one-time owner key, encrypt the bundle, and send ([05](05-NETWORK.md) carries it). Receivers trial-decapsulate at their leisure: **no invoice, no liveness, no round trip**. The scan key can be delegated to an untrusted-for-funds watcher — the viewing/spending split institutions expect.

Address records are published as signed events cross-chained to a PQ root (`kernel/src/address.rs`): whatever bulletin board carries them (see [05](05-NETWORK.md)), authority always rests on the SLH-DSA chain, never the carrier. A quantum-forged carrier identity can deface a profile; it cannot redirect a payment.

## Recovery

One seed derives scan and spend keys; seed + the network's storage layer reconstructs every note and proof. Wallet backup is "write down the seed" — losing a device never loses funds.
