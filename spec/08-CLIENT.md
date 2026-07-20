# 08 · Client (Blacklight)

**One sentence:** The client is a chat app — a fork of White Noise's audited Rust core — where sending money is sending a message.

**Requires:** [06-PAYMENTS](06-PAYMENTS.md)

## The decision (locked)

**Blacklight forks [White Noise](https://www.whitenoise.chat/)** ([whitenoise-rs](https://github.com/parres-hq/whitenoise); fork at [ultravienet/blacklight](https://github.com/ultravienet/blacklight)). Why: chat-first Nostr messenger on the Marmot protocol (MLS over Nostr); **Rust core** (the kernel becomes a dependency, same language); **Least Authority audit, final April 2026** (a money app should start from an audited messaging core); Blossom blobs already integrated (our proof-bundle store); non-profit and community-run; Marmot is an open spec so our extensions publish the same way.

**Licensing:** White Noise is AGPL-3.0, so Blacklight is AGPL-3.0. The kernel is MIT/Apache-2.0 and the AGPL app depends on it — that direction is license-clean and keeps the kernel embeddable by anyone.

Runners-up, for the record: 0xchat/XChat (most features; Dart core → crypto behind FFI), Keychat (right vision, super-app pivot). Feed clients (Damus/Amethyst/Primal) are the wrong shape. Signal was rejected as a foundation: closed network hostile to third-party clients (LibreSignal shut down; Session forced to rebuild its network; Molly limited to server-invisible changes), no public bulletin board for fraud-proof gossip, and its one payments door (MobileCoin) was a founder-level partnership with no API. Signal is a product; Blacklight needs a commons.

## What the fork adds

The wallet crate (kernel types, note store, prover integration), new event kinds (address records, bundle pointers), Blossom bundle transfer, mempool-watching for the *visible* state, record publication (self / receiver / cooperative batch, [03](03-RECORDS.md)), and payment UX where "send $20" is a message bubble. Chat stays MLS (groups open bill-splitting later); Blacklight↔Blacklight traffic wears the PQ envelope, degrading to vanilla NIP-17 only for interop — visibly marked. No server-side software ships with the client; the optional speed layer ([11](11-SPEED-LAYER.md)) would add its own event kinds if ever built.

The stack in one line: **events to the relay, KEM to the human, MLS if you keep talking, receipts for finality.**

## Ecosystem shape: no middleman slot

The pattern to avoid is *protocol → company → users* (how RGB got UTEXO: a company filling protocol gaps becomes a chokepoint). Ultraviolet ships those layers as protocol and NIPs on a network nobody owns: operator roles live inside the protocol with fraud-provable accountability and an L1 escape hatch; issuer bridges are per-issuer; apps are clients, not layers. The first Blacklight operator will *look* like a middleman for a while — the difference is the position is earnable and losable, not architectural.
