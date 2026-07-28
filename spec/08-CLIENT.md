# 08 · Client (Signal fork, iOS)

**One sentence:** The client is a chat app — a fork of Signal — where sending money is sending a message.

**Requires:** [06-PAYMENTS](06-PAYMENTS.md)

## The decision, and what changed

**The client forks [Signal](https://github.com/signalapp/Signal-iOS) (AGPL-3.0), first on iOS, running against a self-hosted [Signal server](https://github.com/signalapp/Signal-Server).**

An earlier draft of this file rejected Signal, and the reasoning was not wrong: closed network hostile to third-party clients, no public bulletin board, no payments API. Every one of those facts is still true. What changed is the **goal**. That draft was optimizing for a permissionless commons, where a carrier that can decline is disqualifying. The goal now is a working implementation good enough to put in front of Signal itself — and under that goal, the closed network stops being an obstacle and becomes the distribution. You do not route around a network you are trying to join.

The consequences of that swap are stated where they land, not buried:

- **Adoption is a business decision, not a technical one.** The fork reaches you and your testers and nobody else, because third-party clients cannot touch the production network. Its value is entirely as a demonstration.
- **We operate a server for the demo.** This costs the protocol its old *nothing to deploy* claim ([05](05-NETWORK.md)), which returns only if Signal ships the message type.
- **Durable storage is now a separate role** ([05](05-NETWORK.md)), because Signal delivers then deletes.

What the swap buys, technically rather than politically: megabyte proof bundles that fit natively, sealed sender instead of a scrapeable public archive, and a carrier whose own transport is already post-quantum. Two of the open transport problems from the audit close by construction.

**Licensing:** this project is MIT throughout. Signal's clients and `libsignal` are AGPL-3.0, and that is *their* licence, not something ours overrides — anyone distributing a client that links Signal's code inherits AGPL obligations whatever our manifests say. The direction is still the clean one (a permissive kernel used by an AGPL application, never the reverse), and the kernel stays embeddable by anyone. Nothing is released yet, so nothing has been triggered.

## The constraint that used to shape this product, and no longer does

**A phone proves its own payments.** Measured 2026-07-27 on an iPhone 17 Pro Max (A19 Pro,
iOS 26.5.2), from a signed app on the device: one complete hop in **0.284–0.314 s using
279 MB** in the hiding configuration, which is the payment format; verification is 1.6–1.7 ms.

**And on the cheapest iPhone Apple sells** — an iPhone 16e (A18), iOS 26.2.1 — the same hop is
**0.331–0.354 s**, only ~1.15× slower, with the prover's own share of memory within 2 MB of the
flagship's. That is the number that matters: the claim is that *a* phone can prove, not that a
flagship can, and a two-tier price gap moves it by a sixth. Proof sizes are byte-identical
across both phones and the desktop build. Reproduce with `ios/UVProbe`
(see [`demo/ios.md`](../demo/ios.md)).

| | On the phone? |
|---|---|
| **Receiving** — verify the incoming proof, check the record, accept the note | **Yes, fully.** Milliseconds, offline, no trust in anyone. |
| **Holding** — notes, keys, balances, history | **Yes, fully.** Bearer state on your device. |
| **Sending** — prove the transition | **Yes, fully.** About a third of a second. |

**Why this section is kept rather than deleted.** Everything above used to say the opposite,
and the reasoning was sound at the time: proving took minutes and gigabytes, so sending had
to be delegated, and a delegated prover necessarily learns the witness — the note secrets,
the amounts, the keys. That was a privacy hole, not a latency footnote, and it forced an
honest v0 of "receive-and-hold is a real self-custodial wallet; sending is a phone plus a
prover."

That constraint was a fact about the **zero-knowledge virtual machine** the protocol used to
run on — 124 s and 9.67 GB per payment — not about this protocol. Replacing it with a
hand-written circuit dissolved the problem instead of mitigating it. The design rule **"no
delegated proving of witnesses"** now costs nothing to keep, so it is kept.

The lesson is worth more than the paragraph it saves: a constraint inherited from a tool can
reshape a whole product, and it stops being true the moment the tool changes. Re-measure
before designing around one.

## What the fork adds

- **The Rust core into iOS via FFI.** This is not novel work in a Signal client: Signal already consumes `libsignal` as a Rust library behind a Swift wrapper, so `kernel` + `wallet` follow an established pattern and an established build. The kernel already cross-compiles to RISC-V for the guest, which is good evidence it travels.
- **A payment message type** carried inside the existing encrypted message, with the bundle as an attachment. Client-side only.
- **Chain view** for records: signet via an Esplora-style endpoint to start. Honest caveat: that endpoint is trusted for *completeness*, not just availability — an omitted record is an invisible failure ([03](03-RECORDS.md), and audit B2 is still open).
- **Mempool watching** for the *visible* state ([06](06-PAYMENTS.md)), the practical assurance that ran a decade of 0-conf retail.
- **Record publication** — self, receiver, or cooperative batch ([03](03-RECORDS.md)).
- **Address exchange in-band** on first contact ([05](05-NETWORK.md)): no profile change, no directory, no server change.
- **Payment UX** where "send $20" is a message bubble, and a proof arriving later upgrades the bubble rather than blocking it.

Chat stays exactly Signal's — we are adding a money path to a messenger, not rebuilding a messenger. Payment traffic between forked clients wears the PQ envelope; there is no degraded interop mode, because the carrier's own transport is already post-quantum.

## Ecosystem shape: the middleman slot moved

The pattern to avoid is *protocol → company → users* (how RGB got UTEXO: a company filling protocol gaps becomes a chokepoint). On a public relay network that risk sat with whoever ran the operator roles. Here it sits somewhere more honest and more concentrated: **the carrier is a single organization**, and that is the trade being made deliberately for reach and for a privacy brand that has earned its reputation.

What limits the damage is that the carrier is structurally unable to steal or forge: validity is client-side proofs behind PQ signatures, double-spend ordering is Bitcoin's, and the server holds ciphertext. The worst a carrier can do is **refuse to carry** — censorship, not theft. That is a real power and it is why the protocol stays carrier-agnostic underneath: the kernel, the wallet, the records, and the proofs contain nothing Signal-specific, so the carrier is replaceable if the relationship ends.
