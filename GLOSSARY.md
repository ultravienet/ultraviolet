# Glossary

One term per concept; the spec uses these words and no synonyms.

| Term | Meaning | Spec |
|---|---|---|
| **note** | the unit of money: a private hash commitment to (contract, value, owner, randomness) | [02](spec/02-NOTES.md) |
| **contract** | an asset: its genesis hash is the `contract_id` | [02](spec/02-NOTES.md) |
| **address record** | published bundle of scan + spend keys, authenticated by an SLH-DSA chain | [02](spec/02-NOTES.md) |
| **scan key** | ML-KEM key others encrypt to; finds your incoming payments; can't spend | [02](spec/02-NOTES.md) |
| **bundle** | one transfer's package: encrypted notes + proof + record pointer (the only word for this; never "consignment") | [06](spec/06-PAYMENTS.md) |
| **nullifier (nf)** | deterministic per-note hash; two spends of one note collide on it | [03](spec/03-RECORDS.md) |
| **record** | the 64 on-chain bytes: `nf ‖ H(bundle)`; first occurrence wins | [03](spec/03-RECORDS.md) |
| **batch** | a cooperative Merkle-batched posting of many records in one OP_RETURN, by any client | [03](spec/03-RECORDS.md) |
| **epoch** | a fixed span of Bitcoin blocks (v1: 6); the protocol's clock for timeouts and disputes | [03](spec/03-RECORDS.md) |
| **hop** | one proven transfer in an asset's history | [04](spec/04-PROOFS.md) |
| **relay** | an ordinary, unmodified Nostr relay doing what relays do: storage and mailbox | [05](spec/05-NETWORK.md) |
| **visible / final** | a payment's two core states: record in Bitcoin's mempool (seconds) / confirmed (~1 block) | [06](spec/06-PAYMENTS.md) |
| **receipt** | *(speed layer, optional)* a notary's signed instant guarantee for one record | [11](spec/11-SPEED-LAYER.md) |
| **fraud proof** | *(speed layer, optional)* two conflicting receipts from one notary — self-contained conviction, spends the bond | [11](spec/11-SPEED-LAYER.md) |
| **bond** | *(speed layer, optional)* a note owned by a notary that a fraud proof can spend | [11](spec/11-SPEED-LAYER.md) |
| **guaranteed** | *(speed layer, optional)* receipt-backed state between visible and final (<1 s) | [11](spec/11-SPEED-LAYER.md) |
| **hash-lock** | note spend condition: preimage before timeout, else refund | [06](spec/06-PAYMENTS.md) |
| **gateway** | a market maker doing atomic hash-locked swaps between Ultraviolet and Lightning | [06](spec/06-PAYMENTS.md) |
| **channel** | a 2-of-2 note updated by co-signed states, highest sequence wins; the weakest tier — assumes liveness, unlike the base rail | [07](spec/07-CHANNELS.md) |
| **Darknoise** | the default payment rail: direct transfers over Nostr, records on Bitcoin | [06](spec/06-PAYMENTS.md) |
| **Blacklight** | the client: a chat app forked from White Noise | [08](spec/08-CLIENT.md) |
| **Ultravienet** | the network and the GitHub org | [00](spec/00-OVERVIEW.md) |
| **M-Day** | the issuer-policy flag day migrating an asset from an old rail | [09](spec/09-INTEROP.md) |
| **quantum-safe / post-quantum** | marketing word / spec word for the same claim; "quantum-proof" is banned | [01](spec/01-CRYPTO.md) |
