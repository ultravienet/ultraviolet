# Ultraviolet

**Money that works like texting — sent in chat, on Bitcoin within the hour, and immune to quantum computers. Carrying it costs the messenger no server changes at all.**

*The spectrum beyond RGB. The light you verify banknotes under.*

Ultraviolet is a clean-sheet successor to RGB: assets live as private notes on your own devices, Bitcoin only orders 64-byte records (first one wins), and a small hand-written STARK proves each transfer, and a receiver checks every hop of a note's history. It travels as chat messages over Signal, which never has to learn it is carrying money. Every primitive that could steal or forge money reduces to one assumption: the hash function. Site: **[ultravienet.github.io/ultraviolet](https://ultravienet.github.io/ultraviolet/)** · **[benchmarks](https://ultravienet.github.io/ultraviolet/benchmarks.html)** (what a payment costs, on a laptop and on a phone) · **[journal](https://ultravienet.github.io/ultraviolet/journal.html)** (how it got here, including what we got wrong).

## Read the spec

Numbered by dependency — each file has one job, states it in one sentence, and only references lower numbers.

| | File | One job |
|---|---|---|
| 00 | [Overview](spec/00-OVERVIEW.md) | the three nouns, one diagram, every locked decision |
| 01 | [Crypto](spec/01-CRYPTO.md) | hashes on the money path; everything else labeled |
| 02 | [Notes](spec/02-NOTES.md) | the money, its owners, addresses, recovery |
| 03 | [Records](spec/03-RECORDS.md) | 64 bytes on Bitcoin; first occurrence wins; epochs |
| 04 | [Proofs](spec/04-PROOFS.md) | one STARK per hop; receiving is O(history) until the accumulator |
| 05 | [Network](spec/05-NETWORK.md) | Signal as carrier; no server changes to carry payments |
| 06 | [Payments](spec/06-PAYMENTS.md) | the default payment; hash-locks; the rail stack |
| 07 | [Channels](spec/07-CHANNELS.md) | kernel-native eltoo; no adaptor signatures |
| 08 | [Client](spec/08-CLIENT.md) | the chat app: a Signal fork, iOS first |
| 09 | [Interop](spec/09-INTEROP.md) | never upgrade old rails; M-Day; Lightning door |
| 10 | [Comparisons](spec/10-COMPARISONS.md) | RGB, Taproot Assets, Shielded CSV, SuperScalar |
| 11 | [Speed layer](spec/11-SPEED-LAYER.md) | *optional*: bonded receipts for sub-second guarantees — shelved until demanded |
| 99 | [Open problems](spec/99-OPEN-PROBLEMS.md) | the only list of what's unfinished |

Plus the **[Glossary](GLOSSARY.md)** — one term per concept, no synonyms.

## The code

Eight crates. One hash on the money path (Poseidon2), one proof system (a
hand-written AIR on upstream Plonky3), one toolchain (stable Rust).

- **[air/](air/)** — the sovereign STARK. WOTS+ over Poseidon2, the domain-separated
  sponge every money-path hash uses, and two circuits: the signature alone, and the
  **full transfer** — commitment openings, nullifier derivation, conservation over
  range-checked limbs, and signature verification in one 1,024 × 457 table. A complete
  hop proves in **~0.075 s / 158 KB / 1.4 ms verify**, or **~0.22 s / 208 KB**
  for a genuinely zero-knowledge proof — and **0.28–0.31 s / 279 MB on an iPhone 17 Pro Max** (0.33–0.35 s on a budget iPhone 16e),
  which is what lets a phone prove its own payments instead of shipping the witness to a
  server ([`ios/UVProbe`](ios/)). Against the zkVM's 124 s / 1,242 KB / 9.67 GB
  ([spec/04](spec/04-PROOFS.md), [benchmarks](https://ultravienet.github.io/ultraviolet/benchmarks.html)).
- **[kernel2/](kernel2/)** — the money path: per-note keys derived from one seed, note
  commitments, nullifiers, transfers, the rolling history digest, and the unchanged
  64-byte record. Byte decodings reject non-canonical field limbs; amounts are 16-bit
  limbs with checked arithmetic.
- **[wallet2/](wallet2/)** — the wallet core, and every discipline a formal model
  demanded: the payload sign-log that replays rather than re-signs, one live transfer
  per note, full-lineage receive validation, and reorg reconciliation.
- **[btc/](btc/)** — records as OP_RETURN transactions, with a persistent
  first-occurrence index.
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
confirmation policy gating acceptance, a double-spend attempt that the sign-log
**replays instead of re-signing**, and a reorg quarantining a note whose ancestry
stopped settling. It self-checks its own claims — including that the replayed
nullifier is byte-identical to the original — and runs in CI.

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
> merging, and bounding the ancestry — all in [spec/99](spec/99-OPEN-PROBLEMS.md).
>
> **On 2026-07-27 adversarial review forged a payment outright** — no key, no secret, money
> from nothing — by exploiting a trace height nothing pinned. Fixed, with two regression
> tests; then the *fix* turned out to reject every honest private payment, and that was caught
> the same way. Neither was found by us. Both are written up in the
> [journal](https://ultravienet.github.io/ultraviolet/journal.html). Consensus circuits need
> professional review before they hold value, and this is why. If you are that reviewer, start at
> **[AUDIT-BRIEF.md](AUDIT-BRIEF.md)** — it names what to attack and why our own tests
> structurally cannot find it. Don't put value on this yet.

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
  already-spent note, the wallet's sign-log replayed the original payload byte for byte
  rather than signing a second one — the never-re-sign discipline (`formal/onetime.qnt`)
  refusing to create the attack. Re-publishing an existing record is a no-op, so the
  funding wallet's balance did not move: **the attempt cost zero on-chain**, and the
  one-time key signed exactly once.
- **Proving is no longer the slow part.** ~0.23 s per hop, so the wait in this run was
  entirely Bitcoin's — waiting for signet blocks.

## Development

```bash
cargo test --workspace                        # 161 tests, real proofs included
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

Formal models live in [`formal/`](formal/) — six Quint models covering supply
conservation, reorgs, off-circuit linkage, WOTS+ one-time keys, the channel dispute
machine, and base-rail liveness. `formal/README.md` records what each one assumes, what
the adversary controls, and the eight modelling and tooling traps that produced
confident-looking wrong answers along the way.

CI (`.github/workflows/ci.yml`) runs fmt, clippy with `-D warnings`, the full test
suite and the end-to-end demo; a second job runs `demo/regtest.sh` against a real
`bitcoind` (four reorg cases); a third typechecks every Quint model and fails if any
source path they cite has gone missing — the rot that actually happened after two crate
renames; and a fourth runs dependency advisories (`cargo audit`: vulnerabilities fail
the build, unmaintained/unsound/yanked crates are reported without failing).

Draft, July 2026. Design + working core + local and signet demos; no professional
security review.
