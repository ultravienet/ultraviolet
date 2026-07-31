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
- **assumption-bounded** — the claim has a **structural** half that is verified in code and a
  **cryptographic hardness** half that no model or test written here can falsify. Counted apart
  from code-tied on purpose (see below).
- **assumption-only** — the claim *is* the assumption. Nothing we can write establishes it.
- **planned** — the model or check does not exist yet.

**Why the two assumption statuses exist, and what happened on 2026-07-30.** S2 and P2 were
rewritten to explain that their structure is verified and their hardness assumed. Because
`claims-coverage.sh` substring-matches the status cell, the phrase "(verified-code)" *inside those
explanations* silently counted both rows as fully code-tied and moved the headline from 14 to 16 —
which happened to be the number a plan had set as a gate. **The number was corrected downward and
the vocabulary added instead.** A hash-preimage assumption is not a gap and not coverage; it is a
third thing, and a matrix that folds it into either one is lying in the direction of whoever reads
the total. The script now matches these tokens first and reports them in their own line.

**The two directions a row can be wrong, both found the same day.** S6 claimed a test that **did
not exist** (nothing perturbed a public value at all). L4 was labelled `model+test` while a
conformance tie for its exact claim **had existed for days** in `conformance_baserail.rs`. The
matrix drifts both ways, so both columns get checked rather than only the pessimistic one.

This file is a Phase-1 deliverable and the seed of the CI matrix; it is expected to change as the
formal spine is built. Rows the proof-auth migration retired are marked **†**.
`formal/claims-coverage.sh` runs in CI: it fails if any row loses a column or a status, and prints
the coverage tally so completeness is a measured number, not an impression.

---

## Safety (no theft, no forgery, no inflation)

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| S1 | A coin is spendable only by someone who knows the preimage of its committed spend anchor | `authorization` `enforced`/`anchorOnly` (**inductive, all depths**) | `kernel2::transfer_prove::verify_hiding` | **model+trace** — `kernel2/tests/conformance_authorization.rs` replays the model's ITF against the real circuit |
| S2 | A third party cannot compute the nullifier of an unspent note | **none possible — argued** | `kernel2/src/nullifier.rs`; note commits to `t=H(nk)` not `nk` | **assumption-bounded** — the claim is one part structure and one part hardness, and only the first can be checked here. **Structure (verified-code):** `nf = H(nk ‖ C)` and nothing published contains `nk` — the note commits to `t = H(nk)`, so `nullifier.rs` tests that a foreign key yields a different nullifier and that the anchor does not reveal it. **Hardness (assumption, not a gap):** computing `nk` from `t` is a Poseidon2 preimage, so no model or test we can write falsifies it; a check that "the hash is not invertible" would be theatre. Named in `AUDIT-BRIEF.md` as the human-review frontier the matrix hands off to |
| S3 | No double-spend: conflicting spends share one `nf`; first occurrence wins | `multihop`, `baserail` | `kernel2/src/nullifier.rs`; `btc/src/index.rs` | **model+trace** — `conformance_multihop.rs` replays the model's race over one nullifier (two real spends of one real note; the loser refused). Drives the rule through the in-memory chain; `btc`'s persistent index has its own first-occurrence tests plus `btc/tests/reorgs_on_a_real_node.rs`, which binds first-occurrence against a live bitcoind through reorgs |
| S4 | Value is conserved exactly — no mint, burn, or wrap | `multihop` `supplyInv` (**inductive, all depths**) | `air/src/authproto_air.rs` c14 (= prod 28); `kernel2/src/amount.rs` | **model + verified-code** — Kani proves, over the production functions for *all* inputs: every `u64` round-trips the limb codec, out-of-range limbs are refused (no aliases), checked add/sum are exact or refuse (never wrap). `kernel2/src/amount.rs` `#[cfg(kani)]`, in CI |
| S5 | Whole-lineage settlement is checked; per-hop does not compose | `multihop` | `wallet2/src/accept.rs` | **model+trace** — `wallet2/tests/conformance_multihop.rs` replays the 8-step inflation counterexample against the real `accept` with a real proof per hop: refused with `LostRace` at the losing ancestor, honest coins accepted (shown to fail if the settlement loop checks only the final hop) |
| S6 | A proof cannot be transplanted to a different transfer (FS binds bundle hash) | — | `air/src/prove.rs`; `air/tests/a_proof_binds_its_whole_statement.rs` | **verified-code** — exhaustive over the closed domain: an honest proof is verified against **all 56 public values perturbed one at a time** (104 forgeries: `+1` and zeroed, minus the already-zero), every one refused. The row said "test-only" citing an `authproto_air.rs` test; a check on 2026-07-30 found **no test perturbed a public value at all**. Fiat–Shamir soundness itself stays an assumption (`AUDIT-BRIEF.md` §3) |
| S7 | Every accepted coin descends from a confirmed issuance record; per-asset sum is exact | `issuance` `strict` (**both supply properties inductive, all depths**) | `wallet2/src/accept.rs`; `kernel2/src/issuance.rs` | **model+trace + verified-code** — `wallet2/tests/conformance_issuance.rs` replays the `strict` acceptance against the real gate; Kani proves the 76-byte record and digest codecs bijective for all inputs (one record, one byte string — nothing a supply count sums can be an alias), `kernel2/src/{issuance,digest}.rs` `#[cfg(kani)]`, in CI. Per-asset sum itself still model-only |
| S8 | Genesis binding by asset ∧ commitment ∧ amount; amount-only and hash-only refused | `issuance` `byAmount`/`globalSum` (**must violate**) | `wallet2/src/accept.rs` | **model+trace** — `wallet2/tests/conformance_issuance.rs` makes the `byAmount` free-mint coin refuse on the real `accept` (shown to fail if the gate reverts to amount-only) |
| S9 | One asset id cannot show two supplies (two genesis notes need two records) | `issuance` `strict` | `wallet2/src/accept.rs`; `cli` anchor import | **model+trace** — the strict trace (seed pinned) publishes two issuances under one asset, both accepted through their own records in `conformance_issuance.rs`; a third genesis riding its siblings' asset and amount is refused by identity |
| S10 | An accepted coin stays valid under reorg or is quarantined; 1-conf is unsafe | `reorg` `shallow`/`deep`/`reconciled` (**inductive, all depths**) | `wallet2/src/reconcile.rs` | **model+trace** — `wallet2/tests/conformance_reorg.rs` replays the `shallow` flip (quarantined on bundle mismatch) and the `genesisUnchecked` orphaned issuance (quarantined with settlement intact) against the real `reconcile` (shown to fail if the genesis half is disabled) |
| S11 | A recoverable bundle is never destroyed (transient vs permanent) | — | `wallet2/src/accept.rs` `is_permanent` (exhaustive match) | verified-code (exhaustive test; no wildcard) |
| S12 | A one-time key never signs twice † | *(retired)* | *(nothing signs)* | **n/a since 2026-07-29** — nothing anywhere in the system signs; `onetime.qnt` retired with it, its questions redirected in `formal/README.md` |
| S13 | A hostile carrier cannot lose or steal funds | `delivery` `keeps`/`discards` (**inductive, all depths** via `deliveryInv`) | transports; `wallet2/src/accept.rs` `is_permanent`; `app/src/commands.rs` `scan_inbox` | model+trace (`app/tests/conformance_delivery.rs`) |
| S14 | Slot reuse cannot disclose a signing key † | `baserail` (slot-collision, partial) | `app/src/slots.rs`; `cli` reservation | **downgraded 2026-07-29** — no signing key exists to disclose (proof-auth); slot reuse is at most a privacy/nullifier-collision concern, never fund loss |

## Liveness

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| L1 | A payment remains possible on the base rail | `baserail` `atomic`/`splitPayment` (**inductive, all depths** via `railInv`/`splitInv`) | `wallet2/src/send.rs` | **model+trace** — `wallet2/tests/conformance_baserail.rs` replays the model's completed split-payment schedule through the real `prepare`/`broadcast`/`accept`: two part-payments of 1, both settled and taken by the real payee, delivered = TARGET |
| L2 | A quarantined-but-good note is restored | `reorg` `reconciled` | `wallet2/src/reconcile.rs` | **model+trace** — `conformance_reorg.rs`: after the trace's flip is reversed by re-mining the honest record, the real pass restores the coin by the full positive check, to `Unspent` |
| L3 | A settled note stays live (replay keeps money spendable) † | *(retired)* | `send` replay path | **holds trivially since 2026-07-29** — proving twice is safe, so replay is just the idempotency cache resending identical bytes; no never-re-sign tension remains |
| L4 | A payment larger than any single note (1+1 pays 2) remains possible | `baserail` `splitPayment` (**inductive, all depths** via `splitInv`) | `cli` split send; `app/src/commands.rs` `plan_send` | **model+trace** — the same tie as L1 and it always was: `wallet2/tests/conformance_baserail.rs` replays the `splitPayment` schedule and asserts `delivered == TARGET` where TARGET is 2 paid as 1 + 1, which is this claim exactly. Corrected from `model+test` on 2026-07-30; the tie existed and the row had not been updated to say so, which is the mirror image of S6, where the row claimed a test that did not exist. **Additionally guarded by an anti-vacuity row**: `baserail splitPayment deliveryIsAllOrNothing` must VIOLATE, i.e. a part must actually arrive while the payment is incomplete. If that row ever stops failing, `split` has stopped modelling a split and this claim has no model behind it |

## Privacy

| # | Claim | Model | Code | Status |
|---|---|---|---|---|
| P1 | Amounts are hidden along a whole lineage (hiding configuration) | **none possible — argued** | `air/src/prove.rs` hiding; `air/tests/hiding_is_randomized.rs` | **assumption-only**, and the most load-bearing row in this file — zero-knowledge is a property of the polynomial commitment scheme, and no test establishes it: a statistical check that two proofs differ (which `hiding_is_randomized.rs` does verify — the same payment never proves to the same bytes twice) is necessary and nowhere near sufficient. **Since 2026-07-29 this is a FUND claim, not a privacy one**: the nullifier key is witness in every spend proof, so a scheme that leaked its witness would leak the thing that moves the money (`[HIDING-UNVERIFIABLE]`, SPEC.md §8.4). Blast radius of one leak is one note, because anchors are one-time. This row is the single strongest argument for the external audit |
| P2 | A payer cannot compute the payee's future nullifier | **none possible — argued** | note spend anchor (§6.3); `wallet2/tests/an_anchor_does_not_reveal_the_genesis_nullifier.rs` | **assumption-bounded**, same shape as S2 — **structure (verified-code):** the payee's `nk` derives from the payee's seed, and a payer only ever receives `t = H(nk)` in the address slot; the committed test asserts an anchor does not reveal the nullifier it stands for. **Hardness (assumption):** recovering `nk` from `t` is again a Poseidon2 preimage |
| P3 | The carrier sees only opaque ciphertext | — | `envelope/tests/the_carrier_sees_only_ciphertext.rs`; and the sealed-wire check in `app/tests/the_whole_system_still_pays.rs` | **verified-code** — over the envelope API in CI, not just one bundle a demo wrote: no marker and **no 32-byte window** of the payload appears anywhere on the wire, the same payload sealed twice differs in every component (so a re-send cannot be fingerprinted), and the round trip is asserted first so leaking nothing cannot pass by the seal being broken. **What leaks is asserted too**: overhead is constant, so wire size reveals payload size — and bundle size grows with lineage length, so a carrier can estimate how many hands a coin passed through. A stated limit, not a hidden one |
| P4 | An observer cannot link a payer to a payee | `privacy` `lone`/`offband`/`decorrelated` | `formal/privacy.qnt` | **model+finding — conditional** — the first model of a *watcher* rather than a thief. Two individually-harmless leaks compose: an on-chain record event and an addressed off-chain delivery. `lone` (the exposed default) **violates** — a payment whose record and delivery fall in one correlation window is linkable, and the observer reads the payer→payee edge with the amount still sealed. Holds only under a mitigation: `offband` (no on-chain event) or `decorrelated` (events split in time). **So payment-graph privacy is a property of traffic and timing, not of the cryptography** — a first cut at a large question, scoped to the pairing leak; a full traffic-analysis adversary is not modelled |

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
   a privacy concern. `onetime.qnt` was retired with the signature; `formal/README.md` says where
   its questions went. **Nothing signature-shaped survives anywhere:** the asset id was the last
   value derived from a one-time public key and became an ordinary sponge hash on 2026-07-30
   (`Domain::AssetId`). Reissuance is *designed* as a hash chain of one-time keys and is not
   built; when it is, it specifies its own mint chain (spec/99 `[SUPPLY]`).

The target end state: no `model-only` on a safety row, no `—` in a Model column for a
protocol-level claim, and every `verified-code` row genuinely checking the production function.
