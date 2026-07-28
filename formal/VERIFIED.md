# Verification ledger

Formal verification has two tiers. The fast bounded suite runs in CI on every
pull request; the deep checks are scheduled and can be run manually because
channels' `naiveSettle` took ~45 minutes at depth 5. Every complete run is
recorded below. Verification without a ledger silently becomes *no*
verification — this file makes "when did we last actually run this?"
answerable.

What CI checks on every pull request: `quint typecheck` over all eight models,
every cited source path, and the fast expected-result matrix. The scheduled
workflow runs the complete matrix and preserves its transcript as an artifact.

A row here is a bounded claim at the depths documented in `formal/README.md`,
not a proof — except multihop's inductive `supplyInv`, which holds at every
transition depth in its fixed five-note universe. `verify.sh` enforces expected
*violations* too: an attack that stops reproducing means the model no longer
models the risk it was written for.

| Date | Commit | Tooling | Checks | Ran by |
|---|---|---|---|---|
| 2026-07-26 | (pre-ledger) | quint 0.32.0 | all documented invariants, by hand during model development | posix4e + agent |
| 2026-07-28 | a29c1e2 | quint 0.32.0 | 59/59 | tdx2 |
