# Verification ledger

Formal verification here is a **manual discipline**: the deep checks are too
slow for CI (channels' `naiveSettle` took ~45 minutes at depth 5), so they run
by hand via `./formal/verify.sh`, and every full run is recorded below. Manual
verification without a ledger silently becomes *no* verification — this file is
what makes "when did we last actually run this?" answerable.

What CI does check, on every push: `quint typecheck` over all six models, and
that every source path the models cite exists — the rot that actually happened
(eight dead citations after two crate renames) rather than the regressions that
have not.

A row here is a bounded claim at the depths documented in `formal/README.md`,
not a proof — except multihop's inductive `supplyInv`, which holds at all
depths. `verify.sh` enforces expected *violations* too: an attack that stops
reproducing means the model no longer models the risk it was written for.

| Date | Commit | Tooling | Checks | Ran by |
|---|---|---|---|---|
| 2026-07-26 | (pre-ledger) | quint 0.32.0 | all documented invariants, by hand during model development | posix4e + agent |
