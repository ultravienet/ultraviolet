# Ultraviolet

**Money that works like texting — sent in chat, on Bitcoin within the hour, and immune to quantum computers. Carrying it costs the messenger no server changes at all.**

*The spectrum beyond RGB. The light you verify banknotes under.*

Ultraviolet is a clean-sheet successor to RGB: assets live as private notes on your own devices, Bitcoin only orders 64-byte records (first one wins), and a small hand-written STARK proves each transfer, and a receiver checks every hop of a note's history. It travels as chat messages over Signal, which never has to learn it is carrying money. Every primitive that could steal or forge money reduces to one assumption: the hash function. Site: **[ultravienet.github.io/ultraviolet](https://ultravienet.github.io/ultraviolet/)** · **[benchmarks](https://ultravienet.github.io/ultraviolet/benchmarks.html)** (what a payment costs, on a laptop and on a phone) · **[journal](https://ultravienet.github.io/ultraviolet/journal.html)** (how it got here, including what we got wrong).

## Read the spec

The specification is a **whitepaper**: [SPEC.md](SPEC.md) — abstract, the problem, design
principles, threat model, cryptographic foundations, notes, records, proofs (including the
measured decision to remove the signature scheme), issuance and supply, delivery, verification,
related work, limitations, and a constraint map for auditors. It reads top to bottom; the
§-references inside it are the map.

Beside it:

- **[spec/99-OPEN-PROBLEMS.md](spec/99-OPEN-PROBLEMS.md)** — the one authoritative list of what
  is unfinished, cited by slug (`[FRONTRUN]`, `[PROOF-AUTH]`, `[ACC]`, …).
- **[formal/CLAIMS.md](formal/CLAIMS.md)** — every whitepaper claim mapped to the model that
  could falsify it and the code that implements it, with a conformance status. A blank is a
  named gap.
- **[Glossary](GLOSSARY.md)** — one term per concept, no synonyms.

Three subsystems (channels, Lightning interop, an optional speed layer) and — on a measured
benchmark — the WOTS+ signature scheme were **deleted** rather than carried as unbuilt scope; the
[journal](https://ultravienet.github.io/ultraviolet/journal.html) has the reasoning for each.

## The code

Eight crates. One hash on the money path (Poseidon2), one proof system (a
hand-written AIR on upstream Plonky3), one toolchain (stable Rust).

- **[air/](air/)** — the sovereign STARK. Poseidon2 and the domain-separated sponge every
  money-path hash uses, and the **proof-native transfer circuit** the money path now runs
  (spec/99 `[PROOF-AUTH]`, since 2026-07-29): commitment openings, nullifier derivation,
  conservation over range-checked limbs, and **authorization by the anchor preimage — no
  signature** — in a 16-row table. A complete hiding hop proves in **~0.02 s / 117 KB / 5 MB** on a
  laptop, an order of magnitude faster and ~23× less memory than the signature circuit it replaced
  (now deleted, along with its `wots_air.rs`/`transfer_air.rs`). *(The on-device figures — 0.28–0.35 s on iPhone — were
  measured on the older signature circuit and are being re-measured on the faster one.)*
  Against the zkVM's 124 s / 1,242 KB / 9.67 GB
  ([§8](SPEC.md#8-transfer-proofs), [benchmarks](https://ultravienet.github.io/ultraviolet/benchmarks.html)).
- **[kernel2/](kernel2/)** — the money path: per-note keys derived from one seed, note
  commitments, nullifiers, transfers, the rolling history digest, and the unchanged
  64-byte record. Byte decodings reject non-canonical field limbs; amounts are 16-bit
  limbs with checked arithmetic.
- **[wallet2/](wallet2/)** — the wallet core, and every discipline a formal model
  demanded: a spend cache that replays a payment byte-for-byte rather than rebuilding it
  (authorization is the anchor preimage — nothing signs), one live transfer per note,
  full-lineage receive validation, and reorg reconciliation.
- **[btc/](btc/)** — records as OP_RETURN transactions, with a persistent
  first-occurrence index, and **mirror sync**: a phone replays bulk pages of
  the chain into that same index and answers its own lookups in-process, so a
  nullifier — a coin's true name — is never sent anywhere. `uv-mirror` serves
  the pages and deliberately offers no endpoint that takes one.
- **[cli/](cli/)** — the `uv` binary: issue, address, send, scan, balance, status, reconcile,
  mine — plus `uv-relay`, a ~200-line bag of opaque blobs so two machines can pay each
  other without a shared filesystem. It holds ciphertext with no addressee on it and
  learns nothing (`demo/relay.sh`, `demo/two-machines.md`).
- **[envelope/](envelope/)** — hybrid ML-KEM-768 + X25519 sealing for what travels
  between wallets. Off the money path by construction: a break here costs privacy,
  never funds.
- **[signal/](signal/)** — a real payment over a real Signal Protocol session:
  Signal's own `libsignal`, a genuine PQXDH handshake, and a sealed bundle carried
  as opaque bytes. A library and a test. Links AGPL code, which is why it is a leaf
  no money-path crate depends on. (`uv --transport signal` takes a different route:
  a linked `signal-cli` daemon, so payments ride Signal's own servers — see
  `demo/signal.md`.)
- **[iosffi/](iosffi/)** + **[ios/](ios/)** — a C ABI over the prover and the minimal
  app that runs it on a physical iPhone, so the on-device numbers can be reproduced
  rather than believed.

The zkVM stack it replaced (SP1 guest, prover, the SHA-256/SLH-DSA kernel, and the
patched `sha2` dependency) has been **deleted**, along with the second CI toolchain.
Its measurements survive as the argument for leaving it, in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html).

## Run the demo

One script, end to end, no network: issuance, a two-hop payment validated in full
(per-hop proofs + linkage + history binding + whole-ancestry settlement), the
confirmation policy gating acceptance, a double-spend attempt the wallet
**replays byte-for-byte instead of rebuilding**, supply counted off the chain and a free-mint
attempt refused, and a reorg quarantining a note whose ancestry stopped settling.
It self-checks its own claims — including that the replayed nullifier is
byte-identical to the original — and runs in CI.

```bash
./demo/local2.sh

# The same money over a network: two homes, one relay, no shared mailbox.
./demo/relay.sh

# Public signet, same code, real OP_RETURN records: see demo/signet.md
```

> **Status: research project, not money.** An independent audit
> ([issue #13](https://github.com/ultravienet/ultraviolet/issues/13)) found four
> consensus-critical gaps; all four are addressed in the current design. A formal model
> then found a worse one — per-hop first-occurrence checks don't compose, so an attacker
> routing a losing branch through a second wallet of their own could make two conforming
> wallets each accept ([`formal/multihop.qnt`](formal/)). **Fixed**: receivers validate
> whole lineages, and the attack is replayed as a test in `wallet2`. Supply conservation
> is now proven at *all* depths by an inductive invariant, not just to a bounded search
> depth. Still open: record front-running (accepted, documented, attacker-pays), proof
> merging, and bounding the ancestry — all in spec/99.
>
> **On 2026-07-27 adversarial review forged a payment outright** — no key, no secret, money
> from nothing — by exploiting a trace height nothing pinned. Fixed, with two regression
> tests; then the *fix* turned out to reject every honest private payment, and that was caught
> the same way. Neither was found by us. Both are written up in the
> [journal](https://ultravienet.github.io/ultraviolet/journal.html). Consensus circuits need
> professional review before they hold value, and this is why. If you are that reviewer, start at
> **[AUDIT-BRIEF.md](AUDIT-BRIEF.md)** — it names what to attack and why our own tests
> structurally cannot find it. Don't put value on this yet.

## Supply you count instead of trust

Creating coins costs a **confirmed Bitcoin transaction**. Issuance publishes a 76-byte
record carrying the **asset id, the amount and the genesis commitment in the clear**;
`uv supply --asset X` filters and sums; and `wallet2::accept` **refuses any coin whose
issuance is not on the chain it is reading** — so an unpublished mint is worthless and an
issuer cannot inflate on the side.

```bash
uv supply --asset X   # this asset's total, read off Bitcoin
uv supply             # every asset on the chain, grouped
uv fees               # what each operation costs — and what costs nothing
```

**There is no gas token.** Fees are bitcoin, and only two operations pay any: publishing
a spend record and publishing an issuance record, each one ordinary transaction.
Receiving, scanning, proving, addresses, `balance`, `supply` and `reconcile` all cost
nothing — `uv fees` lists them explicitly, because "what is free" is the half people
guess wrong. `demo/regtest.sh` measures both record transactions against the estimator
on every CI run; the 13-vByte gap between a spend and an issuance is protocol-determined
and asserted exactly, while the absolute size is wallet-determined and reported rather
than asserted.

Stated as precisely as it deserves, because three things get conflated:

| | Countable? | |
|---|---|---|
| **Total issued, per asset** | **Yes, exactly** | The asset id is on chain in the clear, so an asset's records can be enumerated and summed ([spec/12](SPEC.md#9-issuance-and-supply)) |
| **Conservation between issuances** | **Proven** | Per-hop in-circuit, plus `formal/multihop.qnt`'s inductive `supplyInv` — holds at all depths |
| **Circulating, or per-holder** | **No, deliberately** | Amounts are hidden; seeing them is what the hiding proof exists to prevent |

You cannot "replay the proofs from Bitcoin" — the chain holds `nf ‖ H(bundle)` and proofs
live with holders. It is also unnecessary: conservation is enforced at every hop, so every
coin of an asset descends from one of its confirmed issuance records.

**The residual, reported rather than buried.** Nothing authenticates a record's asset id, so
a stranger can publish a decoy bearing yours. It creates no spendable coin — that needs a
secret only the owner has — but it bears the id, so `uv supply` keeps **attested** and
**unattested** records apart and never adds them together.

**Why this took two attempts.** The first record hashed its details, which binds correctly and
enumerates nothing: you could confirm a record you already knew, never ask which belonged to an
asset. And the first *implementation* of the rule compared amounts rather than identity, so an
attacker could mint against an honest issuer's confirmed record. `formal/issuance.qnt` had the
rule right both times — but **the model does not know what the code says**, so no model run
could have caught the second one. Both weak rules are modules in the model now, and CI fails if
either stops reproducing.

## Live on public signet (2026-07-26)

The full **issuer → Bob → Carol** chain, plus a refused double-spend, settled on a real
Bitcoin network — **published by the current stack**: hand-written STARK, Poseidon2 money
path, no zkVM anywhere.

| Step | Signet transaction | Outcome |
|---|---|---|
| issuer → Bob, 300 | [`e284c5e7…`](https://mempool.space/signet/tx/e284c5e7834ccf98dec811444432e2edf6e437a00f70733e4aa1a97169b03106) (block 314936, 186 vB, 374 sats) | Bob: `accepted 1, rejected 0` |
| Bob → Carol, 100 (two-hop lineage) | [`f8a81f05…`](https://mempool.space/signet/tx/f8a81f054c834ba509b5c292544d168e2209357653454075548fdd5e82626735) (block 314938, 186 vB, 374 sats) | Carol: `accepted 1` — validated **both** hops |
| issuer re-spends the note it already sent | *no new tx — the wallet replayed its original payload* | Dave: `accepted 0, rejected 1` |

Each record is one 64-byte OP_RETURN (`nf ‖ H(bundle)`) at 2 sat/vB, verified on-chain to
begin with the transfer's nullifier. Carol's acceptance did the real work against the live
chain: verified a hiding STARK per hop, checked linkage and the history digest, and
confirmed each hop's record was the **first** occurrence of that nullifier. Final balances
700 + 200 + 100 = the original 1000.

Two properties worth calling out, both observed rather than argued:

- **The double-spend attempt produced no transaction at all.** Pointed at an
  already-spent note, the wallet replayed the original payload byte for byte rather than
  rebuilding a second one. With proof-native authorization nothing signs, so the replay is
  simply the identical bytes; re-publishing an existing record is a no-op, so the funding
  wallet's balance did not move: **the attempt cost zero on-chain**, and no key was ever used.
- **Proving is no longer the slow part.** ~0.23 s per hop, so the wait in this run was
  entirely Bitcoin's — waiting for signet blocks.

## Development

```bash
cargo test --workspace                        # 207 tests, real proofs included
./demo/local2.sh                              # the end-to-end flow, self-checking
cargo run --release -p uv-air --bin measure    # re-measure both circuits
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

Two checks are **manual by design**, because both are too slow for a push and both
silently become nothing if nobody records them. Each has a runbook and a ledger:

```bash
./formal/verify.sh          # every documented invariant   -> formal/VERIFIED.md
python3 air/mutants.py      # delete each constraint, see  -> air/COVERAGE.md
                            # whether any test notices
```

`air/COVERAGE.md` is worth reading before trusting the negative-test suite: the first
sweep found that **eleven of seventeen constraints in `wots_air.rs` survived deletion**
— not redundant, but not isolated by any test either. It explains both reasons and what
an isolating test looks like.

Formal models live in [`formal/`](formal/) — **eight** Quint models covering supply
conservation across hops, on-chain issuance, reorgs and the confirmation policy,
off-circuit ancestry linkage, proof-native spend authorization,
the untrusted delivery carrier, and base-rail liveness. `formal/README.md` records what each one assumes, what the
adversary controls, and the modelling and tooling traps that produced confident-looking
wrong answers along the way; [`formal/CLAIMS.md`](formal/CLAIMS.md) maps every whitepaper
claim to its model and its code.

Two models have been retired rather than carried: **channel dispute rules** (deleted
2026-07-28 with its spec — 27 of the suite's 59 checks then, all about code nobody had
written) and **the one-time-key discipline** (retired 2026-07-29 with the signature itself —
proof-native authorization has no key a second use discloses, so the freeze it modelled
cannot be expressed anymore). The suite stands at **7 models, 35 checks in about ten minutes** — four of them
**all-depths inductive proofs** (supply conservation across hops, both strict-rule supply
claims, and only-the-owner-spends), every bounded `ok` row at depth 8 or better, all of it
about code that ships, on every push in CI.

Below the models sits a second tier, on the *production functions themselves*: **Kani**
(pinned 1.29.0) proves, for every input and with no separate artifact to drift, that the
amount-limb codec round-trips all of `u64` and admits no aliases, that conservation
arithmetic never wraps, and that the digest and 76-byte issuance-record codecs are bijective
— one value, one byte string, for everything keyed by bytes on Bitcoin. Harnesses live in
`#[cfg(kani)]` modules beside the code (`kernel2/src/{amount,digest,issuance}.rs`); CI runs
them on every push.

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, the full test
suite and the end-to-end demo; a second job runs `demo/regtest.sh` against a real
`bitcoind` (four reorg cases); a third typechecks every Quint model and fails if any
source path they cite has gone missing — the rot that actually happened after two crate
renames; and a fourth runs dependency advisories (`cargo audit`: vulnerabilities fail
the build, unmaintained/unsound/yanked crates are reported without failing).

Draft, July 2026. Design + working core + local and signet demos; no professional
security review.
