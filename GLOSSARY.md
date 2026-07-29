# Glossary

One term per concept; the whitepaper uses these words and no synonyms. Reconciled to the
whitepaper (`SPEC.md`) — terms that belonged to deleted subsystems (channels, Lightning interop,
the speed layer) are gone rather than left defining things the system no longer has.

| Term | Meaning | Where |
|---|---|---|
| **note** | the unit of money: a private hash commitment to `(asset, amount, spend anchor, randomness)` | [§6](SPEC.md#6-notes-and-ownership) |
| **asset** | a fungible unit type; its issuance record on Bitcoin names it in the clear | [§9](SPEC.md#9-issuance-and-supply) |
| **spend anchor** | `t = H(nullifier_key)`, committed by the note; spending proves a preimage of it in-circuit | [§6.3](SPEC.md#6-notes-and-ownership) |
| **address** | published one-time payment slots plus a scan key, handed over once | [§6.4](SPEC.md#6-notes-and-ownership) |
| **slot** | one `(index, anchor, randomness)` tuple on an address; each pays once | [§6.4](SPEC.md#6-notes-and-ownership) |
| **scan key** | the ML-KEM-768 + X25519 key a payer seals to; finds incoming payments, cannot spend | [§6.4](SPEC.md#6-notes-and-ownership) |
| **bundle** | one transfer's sealed package: encrypted notes + proof + record pointer (never "consignment") | [§10](SPEC.md#10-delivery) |
| **nullifier (nf)** | `H(nullifier_key ‖ note_commitment)`, deterministic per note; two spends of one note collide on it | [§7.1](SPEC.md#7-records-and-settlement) |
| **record** | the 64 on-chain bytes `nf ‖ H(bundle)`; first occurrence wins | [§7.1](SPEC.md#7-records-and-settlement) |
| **issuance record** | the 76 on-chain bytes `tag ‖ amount ‖ asset ‖ genesis commitment`; supply is their per-asset sum | [§9.1](SPEC.md#9-issuance-and-supply) |
| **attested / unattested** | an issuance record an anchor accounts for / one bearing an asset id nobody vouches for (a decoy) | [§9.4](SPEC.md#9-issuance-and-supply) |
| **batch** | a cooperative Merkle-batched posting of many records under one 32-byte root, by any client | [§7.2](SPEC.md#7-records-and-settlement) |
| **hop** | one proven transfer in a coin's history | [§8](SPEC.md#8-transfer-proofs) |
| **ancestry / lineage** | a coin's chain of hops, oldest first; a receiver binds it to the proof and checks every hop settled | [§7.3](SPEC.md#7-records-and-settlement) |
| **quarantine** | a held note the wallet marks unspendable after a reorg orphaned its ancestry or genesis; released only by the full positive check | [§7.4](SPEC.md#7-records-and-settlement) |
| **carrier** | the messenger that moves sealed bundles and learns nothing about them — Signal by design | [§10](SPEC.md#10-delivery) |
| **durable storage** | a *separate*, unbuilt pluggable role batching and reissuance payloads need; the carrier does not perform it | [§13](SPEC.md#13-limitations-and-open-problems) |
| **visible / final** | a payment's two states: record in Bitcoin's mempool (seconds) / confirmed (~1 block) | [§2](SPEC.md#2-system-overview) |
| **hiding configuration** | the proof format that keeps amounts confidential along a whole lineage; the money-path format | [§8.3](SPEC.md#8-transfer-proofs) |
| **the client** | a chat app forked from Signal, iOS first — design-stage; the linked-device transport is the shipped reality | [§14](SPEC.md#14-status) |
| **mirror sync** | planned leak-free chain view for a phone: bulk record replication, local lookups, N mirrors cross-checked | [§10.3](SPEC.md#10-delivery) |
| **Ultravienet** | the network and the GitHub org | — |
| **quantum-safe / post-quantum** | the marketing word / the technical word for the same claim; "quantum-proof" is banned | [§4](SPEC.md#4-threat-model-and-security-posture) |
