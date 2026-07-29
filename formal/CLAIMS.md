# Claims ↔ model ↔ code — the coverage matrix

**What this is.** Every security, liveness, and privacy claim the whitepaper (`../SPEC.md`) makes,
each mapped to the model that could falsify it and the code that implements it, with a conformance
status. **A blank or `—` in the Model or Code column is a gap**, named here rather than left
silent — which is the whole point, since the sharpest bug this project has had (the free-mint) was
a model and a code that each looked complete while disagreeing.

**How to read the status column.**
- **verified-code** — the actual production function is checked directly (exhaustive test over a
  closed domain, or a bounded model checker over the real code). No separate artifact to drift.
- **model+trace** — a Quint model checks it, and its own traces are replayed against the real code
  (a committed `conformance_*.rs`) so the two cannot silently diverge. A trailing **(planned)** means
  the tie is intended but not yet built — it counts as debt, not coverage.
- **model-only** — a model checks it; the code is *not yet* tied to the model mechanically. This
  is exactly the free-mint exposure and is the debt the `[MODEL-CONFORMANCE]` work pays down.
- **test-only** — Rust tests cover it; no model. Fine for finite/local rules, a gap for
  protocol-level ones.
- **planned** — the model or check does not exist yet.

This file is a Phase-1 deliverable and the seed of the CI matrix; it is expected to change as the
proof-auth migration (§8.4) rewrites the money path and the formal spine is built. Rows that the
migration will delete are marked **†**. `formal/claims-coverage.sh` runs in CI: it fails if any row
loses a column or a status, and prints the coverage tally (code-tied / model-only / test-only) so
completeness is a measured number, not an impression.

---

## Safety (no theft, no forgery, no inflation)

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| S1 | A coin is spendable only by someone who knows the preimage of its committed spend anchor | `authorization` `enforced`/`anchorOnly` (**inductive, all depths**) | `kernel2::transfer_prove::verify_hiding` | **model+trace** — `kernel2/tests/conformance_authorization.rs` replays the model's ITF against the real circuit |
| S2 | A third party cannot compute the nullifier of an unspent note | — | `kernel2/src/nullifier.rs`; note commits to `t=H(nk)` not `nk` | test-only |
| S3 | No double-spend: conflicting spends share one `nf`; first occurrence wins | `multihop`, `baserail` | `kernel2/src/nullifier.rs`; `btc/src/index.rs` | **model+trace** — `conformance_multihop.rs` replays the model's race over one nullifier (two real spends of one real note; the loser refused). Drives the rule through the in-memory chain; `btc`'s persistent index has its own first-occurrence tests plus `demo/regtest.sh` against a real node |
| S4 | Value is conserved exactly — no mint, burn, or wrap | `multihop` `supplyInv` (**inductive, all depths**) | `air/src/authproto_air.rs` c14 (= prod 28); `kernel2/src/amount.rs` | **model + verified-code** — Kani proves, over the production functions for *all* inputs: every `u64` round-trips the limb codec, out-of-range limbs are refused (no aliases), checked add/sum are exact or refuse (never wrap). `kernel2/src/amount.rs` `#[cfg(kani)]`, in CI |
| S5 | Whole-lineage settlement is checked; per-hop does not compose | `multihop` | `wallet2/src/accept.rs` | **model+trace** — `wallet2/tests/conformance_multihop.rs` replays the 8-step inflation counterexample against the real `accept` with a real proof per hop: refused with `LostRace` at the losing ancestor, honest coins accepted (shown to fail if the settlement loop checks only the final hop) |
| S6 | A proof cannot be transplanted to a different transfer (FS binds bundle hash) | — | `air/src/prove.rs`; `authproto_air.rs` test | test-only |
| S7 | Every accepted coin descends from a confirmed issuance record; per-asset sum is exact | `issuance` `strict` (**both supply properties inductive, all depths**) | `wallet2/src/accept.rs`; `kernel2/src/issuance.rs` | **model+trace + verified-code** — `wallet2/tests/conformance_issuance.rs` replays the `strict` acceptance against the real gate; Kani proves the 76-byte record and digest codecs bijective for all inputs (one record, one byte string — nothing a supply count sums can be an alias), `kernel2/src/{issuance,digest}.rs` `#[cfg(kani)]`, in CI. Per-asset sum itself still model-only |
| S8 | Genesis binding by asset ∧ commitment ∧ amount; amount-only and hash-only refused | `issuance` `byAmount`/`globalSum` (**must violate**) | `wallet2/src/accept.rs` | **model+trace** — `wallet2/tests/conformance_issuance.rs` makes the `byAmount` free-mint coin refuse on the real `accept` (shown to fail if the gate reverts to amount-only) |
| S9 | One asset id cannot show two supplies (two genesis notes need two records) | `issuance` `strict` | `wallet2/src/accept.rs`; `cli` anchor import | **model+trace** — the strict trace (seed pinned) publishes two issuances under one asset, both accepted through their own records in `conformance_issuance.rs`; a third genesis riding its siblings' asset and amount is refused by identity |
| S10 | An accepted coin stays valid under reorg or is quarantined; 1-conf is unsafe | `reorg` `shallow`/`deep`/`reconciled` (**inductive, all depths**) | `wallet2/src/reconcile.rs` | **model+trace** — `wallet2/tests/conformance_reorg.rs` replays the `shallow` flip (quarantined on bundle mismatch) and the `genesisUnchecked` orphaned issuance (quarantined with settlement intact) against the real `reconcile` (shown to fail if the genesis half is disabled) |
| S11 | A recoverable bundle is never destroyed (transient vs permanent) | — | `wallet2/src/accept.rs` `is_permanent` (exhaustive match) | verified-code (exhaustive test; no wildcard) |
| S12 | A one-time key never signs twice † | *(retired)* | *(off money path)* | **n/a since 2026-07-29** — nothing on the money path signs (proof-auth); `onetime.qnt` retired with the signature, its story in `formal/README.md` |
| S13 | A hostile carrier cannot lose or steal funds | `delivery` `keeps`/`discards` | transports; `wallet2/src/accept.rs` `is_permanent` | model (target: trace replay vs `is_permanent`) |
| S14 | Slot reuse cannot disclose a signing key † | `baserail` (slot-collision, partial) | `app/src/slots.rs`; `cli` reservation | **downgraded 2026-07-29** — no signing key exists to disclose (proof-auth); slot reuse is at most a privacy/nullifier-collision concern, never fund loss |

## Liveness

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| L1 | A payment remains possible on the base rail | `baserail` `atomic`/`splitPayment` | `wallet2/src/send.rs` | **model+trace** — `wallet2/tests/conformance_baserail.rs` replays the model's completed split-payment schedule through the real `prepare`/`broadcast`/`accept`: two part-payments of 1, both settled and taken by the real payee, delivered = TARGET |
| L2 | A quarantined-but-good note is restored | `reorg` `reconciled` | `wallet2/src/reconcile.rs` | **model+trace** — `conformance_reorg.rs`: after the trace's flip is reversed by re-mining the honest record, the real pass restores the coin by the full positive check, to `Unspent` |
| L3 | A settled note stays live (replay keeps money spendable) † | *(retired)* | `send` replay path | **holds trivially since 2026-07-29** — proving twice is safe, so replay is just the idempotency cache resending identical bytes; no never-re-sign tension remains |
| L4 | A payment larger than any single note (1+1 pays 2) remains possible | `baserail` `splitPayment` | `cli` split send | model+test |

## Privacy

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| P1 | Amounts are hidden along a whole lineage (hiding configuration) | — | `air/src/prove.rs` hiding | test-only (property of the PCS; `[HIDING-UNVERIFIABLE]`) |
| P2 | A payer cannot compute the payee's future nullifier | — | note spend anchor (§6.3) | test-only |
| P3 | The carrier sees only opaque ciphertext | — | `envelope/`; `demo/check_sealed.py` | test-only (relay instrumented to confirm) |

---

## Gaps this matrix makes visible, in priority order

1. **The `[MODEL-CONFORMANCE]` debt is paid.** Every row that was model-only is now model+trace
   on the ITF-replay pattern: S1 (`conformance_authorization`), S7/S8/S9 (`conformance_issuance`),
   S3/S5 (`conformance_multihop` — the inflation counterexample with a real proof per hop),
   S10/L2 (`conformance_reorg` — the flip, the restore, and the orphaned issuance), and L1
   (`conformance_baserail` — the completed split-payment schedule realized through the real send
   path, the one liveness rung). Each safety tie is shown to bite: weakening the checked rule
   fails the test (`formal/traces/README.md` lists the confirmations). The standing discipline
   from here: a new rule ships with its row, its model, and its tie — a matrix blank after a
   feature lands means the discipline failed, and that is the bug to fix.
2. **S6, P1, P2, P3 are test-only with no model.** Proof transplant and the privacy claims have no
   falsifiable model. `delivery.qnt` now covers the carrier (S13); the hiding property (P1) is
   `[HIDING-UNVERIFIABLE]` and becomes fund-critical once proof-auth lands.
3. **† rows resolved by the proof-auth migration (landed 2026-07-29).** S12, S14, L3 were
   consequences of the one-time signature; with it removed from the money path, S12 is n/a (nothing
   signs), L3 holds trivially (proving twice is safe), and S14 is downgraded from key disclosure to
   a privacy concern. `onetime.qnt` was retired with the signature (its findings and retirement are
   recorded in `formal/README.md`); `air/src/wots.rs` survives off the money path — the asset id
   is still an issuer's one-time public key, and the planned mint authority is a hash-chain of
   them — but no spend ever verifies a signature.

The target end state: no `model-only` on a safety row, no `—` in a Model column for a
protocol-level claim, and every `verified-code` row genuinely checking the production function.
