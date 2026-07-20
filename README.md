# Ultraviolet

**Money that works like texting — sent in chat, on Bitcoin within the hour, and immune to quantum computers. The only software anyone runs is a chat app.**

*The spectrum beyond RGB. The light you verify banknotes under.*

Ultraviolet is a clean-sheet successor to RGB: assets live as private notes on your own devices, Bitcoin only orders 64-byte records (first one wins), and one constant-size recursive STARK proves any history. The network is today's Nostr, unmodified — zero new server software. Every primitive that could steal or forge money reduces to one assumption: the hash function. Site: **[ultravienet.github.io/ultraviolet](https://ultravienet.github.io/ultraviolet/)**.

## Read the spec

Numbered by dependency — each file has one job, states it in one sentence, and only references lower numbers.

| | File | One job |
|---|---|---|
| 00 | [Overview](spec/00-OVERVIEW.md) | the three nouns, one diagram, every locked decision |
| 01 | [Crypto](spec/01-CRYPTO.md) | hashes on the money path; everything else labeled |
| 02 | [Notes](spec/02-NOTES.md) | the money, its owners, addresses, recovery |
| 03 | [Records](spec/03-RECORDS.md) | 64 bytes on Bitcoin; first occurrence wins; epochs |
| 04 | [Proofs](spec/04-PROOFS.md) | recursion; O(1) receive, measured |
| 05 | [Network](spec/05-NETWORK.md) | ordinary Nostr, unmodified; zero new server software |
| 06 | [Payments](spec/06-PAYMENTS.md) | Darknoise: the default payment; hash-locks; four rails |
| 07 | [Channels](spec/07-CHANNELS.md) | kernel-native eltoo; no adaptor signatures |
| 08 | [Client](spec/08-CLIENT.md) | Blacklight: the chat app (White Noise fork) |
| 09 | [Interop](spec/09-INTEROP.md) | never upgrade old rails; M-Day; Lightning door |
| 10 | [Comparisons](spec/10-COMPARISONS.md) | RGB, Taproot Assets, Shielded CSV, SuperScalar |
| 11 | [Speed layer](spec/11-SPEED-LAYER.md) | *optional*: bonded receipts for sub-second guarantees — shelved until demanded |
| 99 | [Open problems](spec/99-OPEN-PROBLEMS.md) | the only list of what's unfinished |

Plus the **[Glossary](GLOSSARY.md)** — one term per concept, no synonyms.

## The code

- **[kernel/](kernel/)** — `ultraviolet-kernel` (MIT OR Apache-2.0): notes, nullifiers, transfers, SLH-DSA signatures, hash-locks, channel state with the never-re-sign `SignGuard`, and the optional speed layer's receipt/fraud-proof types. 27 tests.
- **[guest/](guest/) + [prover/](prover/)** — the SP1 program and driver: `cargo run --release -p uv-prover` proves a two-hop history and verifies it with one 1,242 KB proof (constant across depth), authorized by a real 7,856-byte SLH-DSA signature. Measured 2026-07-22 on a laptop CPU.
- **[wallet/](wallet/) + [prove/](prove/) + [cli/](cli/)** — the POC wallet: hybrid ML-KEM-768+X25519 note encryption, deterministic identities, a `Chain`/`Transport` abstraction (in-process + file-backed mocks; Bitcoin/Nostr backends staged next), and the `uv` CLI.
- Client fork base: [ultravienet/blacklight](https://github.com/ultravienet/blacklight) (AGPL-3.0, unmodified from White Noise upstream for now).

## Run the POC

Stage A runs a full **Alice → Bob → Carol** payment loop locally — no network, a file-backed mock of Bitcoin's first-occurrence rule, filesystem transport standing in for Nostr:

```bash
cargo build --release -p uv-cli
./demo/local.sh
```

It issues an asset, sends it, receives-and-verifies (one recursive STARK per hop), re-spends across a second hop (proving recursion), and demonstrates that a double-spend is rejected by first-occurrence. Proving is ~1 min/hop on a laptop CPU. Regtest bitcoind and signet backends (real OP_RETURN records) plus Nostr transport are the next POC stages.

Draft, July 2026. Design + working core + local POC; no security review yet.
