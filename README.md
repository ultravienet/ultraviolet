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

Everything here describes what is built. Designs that were measured and rejected, or specified
and never built, were **deleted** rather than carried — each with its reasoning, in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html).

## The code

Eight crates. One hash on the money path (Poseidon2), one proof system (a
hand-written AIR on upstream Plonky3), one toolchain (stable Rust).

- **[air/](air/)** — the sovereign STARK. Poseidon2 and the domain-separated sponge every
  money-path hash uses, and the **proof-native transfer circuit** the money path now runs
  (spec/99 `[PROOF-AUTH]`, since 2026-07-29): commitment openings, nullifier derivation,
  conservation over range-checked limbs, and **authorization by the anchor preimage — no
  signature** — in a 16-row table. A complete hiding hop proves in **~0.02 s / 117 KB / 5 MB** on a
  laptop, an order of magnitude faster and ~23× less memory than the design it replaced. On an
  **iPhone 16e (A18)** — the cheapest one Apple sells — a hiding hop proves in **0.006–0.012 s**
  using **1 MB** beyond the app's own footprint, proof bytes identical to the Mac's (signed build,
  2026-07-29). Two earlier designs were measured and deleted; the numbers that condemned them
  are in the [journal](https://ultravienet.github.io/ultraviolet/journal.html)
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
  nullifier — a coin's true name — is never sent anywhere. `uv-mirror` (a binary in
  this crate) serves the pages and deliberately offers no endpoint that takes one.
- **[app/](app/)** — the command layer every client shares: issue, address, send,
  scan, balance, status, reconcile. It returns values, never prints, never exits —
  so the same rule that decides whether money moves runs identically on a phone and
  in a test. `send` returns the sealed bundle for the caller to *deliver*; delivery
  is the one thing this layer does not do, because it differs per client.
- **[envelope/](envelope/)** — hybrid ML-KEM-768 + X25519 sealing for what travels
  between wallets. Off the money path by construction: a break here costs privacy,
  never funds.
- **[iosffi/](iosffi/)** + **[ios/](ios/)** — `uv_call(json) -> json`, a C ABI over
  `app/`, and **UVWallet**, the SwiftUI app on top of it. No protocol rule is
  implemented in Swift: a second implementation of a rule that decides whether money
  moves is a second chance to get it wrong. It reads public signet through a mirror on
  a physical iPhone, and its self-test measures the prover on the phone, so the
  on-device numbers can be reproduced rather than believed. **The FFI door speaks
  `send` and `scan`, which is the seam a chat-app client — the planned Signal fork —
  carries payments over.**

## Run the tests

The whole payment cycle is a Rust test over `app/`, the shared command layer:
issuance, a two-hop payment validated in full (per-hop proofs + linkage + history
binding + whole-ancestry settlement), the confirmation policy, a double-spend the
wallet **replays byte-for-byte instead of rebuilding**, supply counted off the
chain, and a reorg quarantining a note whose ancestry stopped settling. It runs
the exact code path a phone does through the FFI.

```bash
# The end-to-end flow, driving the shared command layer:
cargo test -p uv-app --test the_whole_system_still_pays

# The same payment through the FFI's JSON door — the seam the iOS client uses:
cargo test -p uv-iosffi paying_through_the_door

# Reorgs against a real bitcoind: a record surviving a re-mine, a record lost
# rolling the index back, first-occurrence binding the earliest confirmed record.
# Skips (green) if bitcoind is not on PATH.
cargo test -p uv-btc --test reorgs_on_a_real_node -- --test-threads=1

# Everything:
cargo test --workspace
```

> A real payment crossed **Signal's own production servers** on 2026-07-28, carried
> by `signal-cli` as a linked device. The client that ships that natively is a
> fork of Signal-iOS, in progress; it sends through the same FFI door the tests
> above exercise. See the [journal](https://ultravienet.github.io/ultraviolet/journal.html).

> **Status: research project, not money.** An independent audit
> ([issue #13](https://github.com/ultravienet/ultraviolet/issues/13)) found four
> consensus-critical gaps; all four are addressed in the current design. A formal model
> then found a worse one — per-hop first-occurrence checks don't compose, so an attacker
> routing a losing branch through a second wallet of their own could make two conforming
> wallets each accept ([`formal/multihop.qnt`](formal/)). **Fixed**: receivers validate
> whole lineages, and the attack is replayed as a test in `wallet2`. Supply conservation
> is now proven at *all* depths by an inductive invariant, not just to a bounded search
> depth. Still open: record front-running (cheap to grief — the attacker pays cents to strand any note; the defence is out-of-band submission, owed not built), proof
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
`app::commands::supply` filters and sums per asset; and `wallet2::accept` **refuses any coin whose
issuance is not on the chain it is reading** — so an unpublished mint is worthless and an
issuer cannot inflate on the side.

**There is no gas token.** Fees are bitcoin, and only two operations pay any: publishing
a spend record and publishing an issuance record, each one ordinary transaction.
Receiving, scanning, proving, addresses, balance, supply and reconcile all cost
nothing. `btc/src/lib.rs`'s fee estimator models a record transaction as one taproot
input, the `OP_RETURN`, and one change output; the 13-vByte gap between a spend and an
issuance is protocol-determined
and asserted exactly, while the absolute size is wallet-determined and reported rather
than asserted.

Stated as precisely as it deserves, because three things get conflated:

| | Countable? | |
|---|---|---|
| **Total issued, per asset** | **Yes, exactly** | The asset id is on chain in the clear, so an asset's records can be enumerated and summed ([SPEC.md §9](SPEC.md#9-issuance-and-supply)) |
| **Conservation between issuances** | **Proven** | Per-hop in-circuit, plus `formal/multihop.qnt`'s inductive `supplyInv` — holds at all depths |
| **Circulating, or per-holder** | **No, deliberately** | Amounts are hidden; seeing them is what the hiding proof exists to prevent |

You cannot "replay the proofs from Bitcoin" — the chain holds `nf ‖ H(bundle)` and proofs
live with holders. It is also unnecessary: conservation is enforced at every hop, so every
coin of an asset descends from one of its confirmed issuance records.

**The residual, reported rather than buried.** Nothing authenticates a record's asset id, so
a stranger can publish a decoy bearing yours. It creates no spendable coin — that needs a
secret only the owner has — but it bears the id, so `supply` keeps **attested** and
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
path, authorization by anchor preimage.

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
cargo test --workspace                        # 237 tests, real proofs included
cargo test -p uv-app --test the_whole_system_still_pays   # the end-to-end flow
cargo run --release -p uv-air --bin measure    # re-measure the circuit
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

Two checks are **manual by design**, because both are too slow for a push and both
silently become nothing if nobody records them. Each has a runbook and a ledger:

```bash
./formal/verify.sh          # every documented invariant   -> formal/VERIFIED.md
python3 air/mutants.py      # delete each constraint, see  -> air/COVERAGE.md
                            # whether any test notices
```

`air/COVERAGE.md` is worth reading before trusting the negative-test suite. The sweep
currently kills **16 of 16**, but it got there: the first run left eleven of seventeen
constraints deletable with every test still green — not redundant, just not isolated by
anything. The file explains what an isolating test looks like, and what the sweep still
cannot see.

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
cannot be expressed anymore). The suite stands at **8 models, 73 checks** — **twelve of them
all-depths inductive proofs**, and **every model now has at least one**: supply conservation across
hops, both strict-rule supply claims, only-the-owner-spends, both reorg reconciliation claims,
no-spliced-history, no-settled-payment-lost, and four in `baserail`. Every bounded `ok` row sits at
depth 8 or better, all of it about code that ships, on every push in CI.

**The last two models to get an all-depths proof were the two liveness models**, which was
backwards: they are the ones that say whether a payment can be *made* at all, and every safety model
was proved before either of them. One module stays bounded on purpose — its counter is genuinely
unbounded, and capping it would risk bounding away the counterexample it exists to produce.

**Each of the seven is paired with a check that the proof FAILS on the variant that drops the rule
it depends on**, which matters more than the count: an inductive invariant that holds whether or
not the protocol enforces its rule is proving something about the model rather than the system,
and nothing else in a green run would say so. Six of those pairs were added on 2026-07-30, after a
comment claiming they already existed turned out to be false.

Below the models sits a second tier, on the *production functions themselves*: **Kani**
(pinned 1.29.0) proves, for every input and with no separate artifact to drift, that the
amount-limb codec round-trips all of `u64` and admits no aliases, that conservation
arithmetic never wraps, and that the digest and 76-byte issuance-record codecs are bijective
— one value, one byte string, for everything keyed by bytes on Bitcoin. Harnesses live in
`#[cfg(kani)]` modules beside the code (`kernel2/src/{amount,digest,issuance}.rs`); CI runs
them on every push.

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, the full test
suite (including the end-to-end flow over `app/`); a second job runs the reorg suite
against a real `bitcoind`; a third typechecks every Quint model and fails if any
source path they cite has gone missing — the rot that actually happened after two crate
renames; and a fourth runs dependency advisories (`cargo audit`: vulnerabilities fail
the build, unmaintained/unsound/yanked crates are reported without failing).

Draft, July 2026. Design + working core + local and signet demos; no professional
security review.
