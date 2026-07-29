# Verification ledger

Formal verification here is a **manual discipline**: the deep checks are too
slow for CI — the removed `channels` model's `naiveSettle` took ~45 minutes at
depth 5, which was the whole of it. **Since its removal the suite finishes in about
five minutes and now runs in CI on every push.** This ledger records hand-runs on
real hardware, which are still worth doing but are no longer the only thing
between a regression and nobody noticing. They run
by hand via `./formal/verify.sh`, and every full run is recorded below. Manual
verification without a ledger silently becomes *no* verification — this file is
what makes "when did we last actually run this?" answerable.

What CI does check, on every push: `quint typecheck` over all seven models, and
that every source path the models cite exists — the rot that actually happened
(eight dead citations after two crate renames) rather than the regressions that
have not.

A row here is a bounded claim at the depths documented in `formal/README.md`,
not a proof — except the six inductive rows (multihop's `noInflation`,
issuance's two supply properties, authorization's `onlyOwnerSpends`, and
reorg's two reconciliation claims), which hold at all depths. `verify.sh` enforces expected *violations* too: an attack that stops
reproducing means the model no longer models the risk it was written for.

**The subject, not the commit.** A verification result is about the `.qnt` files
and nothing else — `./scripts/subject-hash.sh formal/*.qnt`. This column held a
git commit, which cannot resolve here: the repository keeps one commit, amended
forever. If the subject hash matches, the row still describes the models in front
of you.

| Date | Subject (`.qnt` files) | Tooling | Checks | Ran by |
|---|---|---|---|---|
| 2026-07-26 | *(pre-ledger)* | quint 0.32.0 | all documented invariants, by hand during model development | posix4e + agent |
| 2026-07-28 | `e52053d3e7c108a5` | quint 0.32.0 | subject hash adopted; models unchanged since the row above | agent |
| 2026-07-28 | `dc5cbb968c6199e9` | quint 0.32.0 | 4/4 issuance rows, incl. the new `byAmount` free-mint counterexample | agent |
| 2026-07-28 | `dbbfedd795e5d8c1` | quint 0.32.0 | **FULL suite, 59/59** — every model, every documented invariant, including the new `globalSum`, `genesisUnchecked` and `genesisChecked` rows. The run reported 60 checks with 1 regression: `baserail ideal`, a **dead row** naming a module renamed to `atomic` long ago that no full run since had caught. Row removed and `baserail` re-run 9/9; `check-refs.sh` now validates module names in CI so the next one fails in seconds. | agent |
| 2026-07-28 | `c9abc6aff5213205` | quint 0.32.0 | **FULL suite, 32/32, ~5 min** — after deleting `channels.qnt` (27 checks, all of unbuilt dispute rules, and the only slow model). Every bounded `ok` row now runs at depth 8 or better; none sit at 5–6 any more. **This run is now a CI step**, not only a hand-run. | agent |
| 2026-07-28 | `186d45c720806beb` | quint 0.32.0 | **35/35, seven models** — added `authorization.qnt`: proof-native spend auth holds (`enforced`), the public-anchor strawman lets a forger steal (`anchorOnly`, violates). The WOTS+-replacement's safety claim now has a model (SPEC.md S1). | agent |
| 2026-07-28 | `aa4d5d500549573d` | quint 0.32.0 | **37/37, eight models** — added `delivery.qnt`: a hostile carrier cannot lose funds (`keeps`), but discarding a bundle on a transient verdict does (`discards`, violates) — the `ViewIncomplete` regression as a permanent guard (SPEC.md S13). | agent |
| 2026-07-29 | `2f4a7bad4318b14b` | quint 0.32.0 | **FULL suite, 32/32, ~5.5 min, seven models** — after retiring `onetime.qnt` with the signature itself (proof-native auth has no key a second use discloses; its successor for the question that remains is `authorization.qnt`). `baserail.qnt` premises re-derived for proof-native auth, comments only: all 9 rows unchanged, because the model never leaned on signatures. | agent |
| 2026-07-29 | `4f5cb2e225a19ae9` | quint 0.32.0 | **FULL suite, 35/35 — three new all-depths proofs.** `authorization.enforced onlyOwnerSpends` inductive via `authInv` (typeOK + preimage knowledge never spreads, ~0.3 s); `issuance.strict` `supplyIsKnown` AND `assetSupplyIsKnown` inductive via its `supplyInv` (~100 s each — the strengthening needed `nextLink == idCounter`, whose absence Apalache demonstrated with a drifted-counters start state). Four inductive rows total with multihop's; every remaining bounded row unchanged. | agent |
| 2026-07-29 | `915fee9627edb8c2` | quint 0.32.0 | **37/37 — two more all-depths proofs.** `reorg.reconciled` `acceptedStaysValid` via `reorgInv` and `acceptedHasLiveGenesis` via `genesisInv`, ~4 s each: six inductive rows now. Also this session: `linkage.qnt` gained a strengthening (`linkInv`, with `uniqueIds`/`freshIds` to collapse `trulyDescends`' nested existentials) whose proof **the tool cannot do at this encoding**: 4 GB heap dies, 16 GB thrashed a 16 GB laptop, and a 64 GB heap on a 243 GB / 64-core box returned `table overflow` after 22 minutes — a Z3 internal limit, so more hardware is not the answer. Linkage stays a bounded row; the attempt, the cause (`trulyDescends`' nested existentials under an arbitrary start state) and the named next idea are written up in `formal/README.md` rather than hidden. Note for anyone retrying: quint hardcodes `-Xmx4096m` for the server it spawns, so a bigger heap needs `apalache.jar server` started by hand plus `--server-endpoint`. | agent |
