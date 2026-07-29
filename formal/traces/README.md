# Model traces, frozen for conformance

These `.itf.json` files are executions of the Quint models (Informal Trace
Format), committed as the model's **frozen testimony**. The Rust conformance
tests replay them against the real code:

- `authorization_*.itf.json` → `kernel2/tests/conformance_authorization.rs`
  drives `verify_hiding` and requires the real circuit to agree with the
  model on every spend (the owner spends; the forger cannot).
- `issuance_*.itf.json` → `wallet2/tests/conformance_issuance.rs` drives the
  real `accept` genesis gate: the `strict` trace's accepted coins clear it, and
  the `byAmount` free-mint coin — accepted in the model against a same-amount
  sibling — is refused by it. This is the drift that actually shipped, now under
  a model-derived test.
- `multihop_*.itf.json` → `wallet2/tests/conformance_multihop.rs` replays the
  8-step inflation counterexample — per-hop checks do not compose — against the
  real `accept`, with real notes and a real proof per hop: the coin whose final
  hop won but whose ancestor lost must be refused with `LostRace` at that
  ancestor, and every honestly-won coin (in both traces) must be accepted.
- `reorg_*.itf.json` → `wallet2/tests/conformance_reorg.rs` replays the two
  reorg counterexamples against the real `reconcile`: the coin whose first
  occurrence a reorg flipped must be quarantined (and restored by the full
  positive check when the honest record is re-mined), and the coin whose
  issuance a reorg orphaned must be quarantined even with its own settlement
  intact.
- `baserail_splitPayment.itf.json` → `wallet2/tests/conformance_baserail.rs`,
  the liveness rung: the model's completed split-payment schedule (two parts,
  both settled, delivered = TARGET) must complete through the real
  `prepare`/`broadcast`/`accept`, end to end, real proofs included.

This is the `[MODEL-CONFORMANCE]` bridge (SPEC.md §11.3): the gap that produced
the free-mint bug was a model and a code that each looked complete while
disagreeing. Freezing the model's own executions as test vectors ties the two
mechanically — a code change that diverges from the model fails a test derived
from the model, not from a human remembering to write it. (Confirmed the ties
bite: reverting the genesis gate to an amount-only check makes
`conformance_issuance` fail on the free mint; weakening the settlement loop to
check only the final hop makes `conformance_multihop` fail on the inflation
coin; disabling `reconcile`'s genesis half makes `conformance_reorg` fail on
the orphaned issuance.)

**Regenerate only when a model changes**, with `./formal/regen-traces.sh`, then
re-run the conformance tests and review any change to what the code must do — a
changed trace is a review event, not a refresh. CI does not regenerate them
(the Rust tests need no quint); the committed traces are the model as it stood.
