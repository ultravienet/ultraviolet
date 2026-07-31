# How the eight models compose — the assume/guarantee graph

**The problem this file exists for.** The sharpest bug this project has had was not inside a
model. The free mint lived in the **gap between** models: each one looked complete, each one
assumed the other had a rule covered, and nothing anywhere checked that the assumptions any model
made were actually discharged by another. Seven separately-green models can add up to a hole.

The obvious fix is one composed model of everything. **That was tried and rejected on measurement,
not taste** — see the last section. What is here instead is the honest alternative the plan allowed:
**explicitly layered models with a stated composition**, plus a script (`formal/compose-check.sh`) that
fails when an assumption has no discharger, so the free-mint *shape* of bug becomes a build error
rather than a thing somebody has to notice.

---

## The layers

Nothing in a lower layer may assume anything from a higher one. A cycle in the graph would mean two
models each leaning on the other, which is how the free mint survived.

```
  layer 4  privacy ...................... an OBSERVER cannot link payer to payee (orthogonal)
  layer 3  delivery ..................... the carrier is untrusted for funds
  layer 2  linkage · multihop · issuance · reorg · baserail
  layer 1  authorization ................. a spend is authorized
  layer 0  the cryptographic assumptions .. Poseidon2, Keccak, FRI, Fiat-Shamir
```

**Every layer now carries at least one all-depths proof.** That was not true until
2026-07-30: the two **liveness** models — `baserail` at layer 2 and `delivery` at layer 3 — had no
inductive row of any kind, while all five safety models did. Since the liveness properties are the
ones that say what the protocol can actually *do*, the composition graph read as though its weakest
layer were the one describing whether a payment is possible at all. `formal/verify.sh` now runs 12
inductive rows across all eight models, each with a falsification partner.

## Layer 0 — the assumptions no model discharges

These are stated here once so that "assumed sound" in seven file headers means *this list* and not
seven slightly different lists. **Nothing in `formal/` establishes any of them**; they are the
frontier the matrix hands to human review (`AUDIT-BRIEF.md`), and each is tracked in
`formal/CLAIMS.md` under an `assumption-bounded` or `assumption-only` status.

| # | Assumption | Discharged by | Claim |
|---|---|---|---|
| A1 | Poseidon2 preimage resistance — knowing `t = H(nk)` does not yield `nk` | **nobody. Assumed.** | S2, P2 |
| A2 | Fiat–Shamir binds a proof to its whole statement — **and the challenger that does the binding is Keccak, so this depends on A7** | `air/tests/a_proof_binds_its_whole_statement.rs` checks the *consequence* exhaustively over all 56 public values; the soundness of FS itself is **assumed** | S6 |
| A3 | The proof system is zero-knowledge — a proof does not leak its witness | **nobody. Assumed**, and since 2026-07-29 this is a **fund** assumption, because the nullifier key is witness in every spend proof | P1 |
| A4 | A verifying proof means the transition was well-formed and authorized | `air`'s constraint tests + the per-column probe + the mutation sweep, all of which check that our rules are load-bearing — **not** that they are complete | S1, S4 |
| A5 | Bitcoin orders transactions and does not reorganise beyond the confirmation margin | `formal/reorg.qnt` models the margin's *consequences*; the margin's adequacy is an economic assumption | S10 |
| A7 | **Keccak is collision- and preimage-resistant.** The proof system commits with it: the trace Merkle tree, FRI folding, and the Fiat–Shamir challenger are all Keccak (`air/src/prove.rs:44-57`), so A2 and A4 both rest on it. **Added 2026-07-30** — it was load-bearing in every proof for months and named in no document, which is why the layer-0 count moved from 6 to 7 without any code changing. Discharged by **nobody. Assumed** — and it is the *least* worrying assumption here, Keccak being SHA-3. | S2, P2, and every claim resting on A2 or A4 |
| A6 | The seal (ML-KEM-768 + X25519 + ChaCha20-Poly1305) is secure | `envelope/tests/the_carrier_sees_only_ciphertext.rs` checks the *structure*; the cryptography is **assumed** — and off the money path by construction, so a break costs privacy, never funds | P3 |

## Layer 1 — `formal/authorization.qnt`

**Assumes:** A1 (a party who does not know a preimage cannot produce it), A2.

**Guarantees:** only a party knowing the preimage of a note's committed spend anchor can spend it
(`onlyOwnerSpends`, **inductive, all depths**), and such a party is not locked out
(`ownerCanSpend`). Falsified without the rule: `anchorOnly` lets a forger steal.

**Every layer-2 model consumes this guarantee** as "a verifying proof attests the transition was
well-formed and authorized". That sentence appears in four file headers; it means exactly
`formal/authorization.qnt`'s guarantee plus A4, and nothing more.

## Layer 2 — the four things a proof does *not* attest

Each of these exists because a verifying proof is silent about something, and the silence is the
attack surface. **This is the layer where the free mint lived.**

| Model | Consumes | What a proof does not attest | Guarantees |
|---|---|---|---|
| `linkage` | layer 1, A4 | that the note a hop spends **ever existed** | `noSplicedHistoryG` — no accepted coin has a fabricated ancestor (**inductive, all depths**, via a ghost variable; `formal/README.md` has the one hand-discharged step) |
| `multihop` | layer 1, A4, `linkage` | that the ancestors' records **won their races** | `noInflation` — per-hop settlement does not compose, whole-lineage does (**inductive, all depths**) |
| `issuance` | layer 1, A4 | that the coin descends from a **confirmed issuance** | `supplyIsKnown`, `assetSupplyIsKnown` (**both inductive, all depths**), `onlyMintKeyIssues` |
| `reorg` | A5 | that the chain **will not move** under a settled coin | `acceptedStaysValid`, `acceptedHasLiveGenesis` (**both inductive, all depths**) |
| `baserail` | layer 1 | anything about **liveness** — a proof says a payment is valid, not that it can be made | `paymentRemainsPossible` (**inductive, all depths**, under `atomic` and `splitPayment`), `nobodyElseGetsPaid` (**inductive, all depths**, under `griefable` and `splitGriefed` — i.e. with the adversary on) |

**The interaction that matters, and that no single model states.** `linkage` guarantees a coin's
ancestry is real; `multihop` guarantees every ancestor's record won; `issuance` guarantees the
oldest ancestor is a confirmed mint; `reorg` guarantees all three keep holding as the chain moves.
**Any one of the four missing makes the other three insufficient** — that is the composition, and
it is the sentence the free mint would have contradicted.

## Layer 3 — `formal/delivery.qnt`

**Assumes:** A6 (the seal), and layer 2's whole result (a settled record decides a payment
independently of whether a message arrived).

**Guarantees:** `noSettledPaymentLost` — no carrier behaviour loses money (**inductive, all
depths**, via `deliveryInv` = *the payment is always either already taken or still re-sendable*).
Falsified without the rule: `discards` loses a settled payment, which is the `ViewIncomplete` bug
that shipped, and the induction fails there at the step case.

## Layer 4 — `formal/privacy.qnt` (orthogonal)

**A different kind of property, and placed apart on purpose.** Every layer below is a *safety or
liveness* guarantee about the money — nothing is stolen, nothing is lost. This one is about a
**leak**: what an observer who only watches can infer. It sits above delivery because it observes
the delivered thing, but it is not in the money-safety chain — no layer-2 model consumes it, and a
break here costs privacy, never funds.

**Assumes:** nothing from the layers below (it is orthogonal). It does assume the seal hides the
amount (A6), which is the *other* privacy axis and is out of scope here.

**Guarantees — conditionally.** `unlinkable` — an observer cannot correctly pair a payment's
on-chain record with its off-chain delivery — holds **only** under a mitigation: out-of-band record
submission (`offband`), or decorrelating the two events in time (`decorrelated`). It **fails** in
the exposed default (`lone`): a lone payment whose record and delivery land in one correlation
window is linkable, and the observer reads the payer→payee edge with the amount still sealed. So
payment-graph privacy is a property of *traffic and timing*, not of the cryptography — the first
model to say so, and the reason `[HIDING-UNVERIFIABLE]`'s "privacy is only as good as the least
careful holder" now has a second sentence: *and the least busy channel*.

## What is deliberately outside every model

- **The wallet's own storage ordering** (durable-before-irreversible). Enforced by type-state in
  `wallet2`, not modelled. A `[SLOT-COLLISION]`-shaped fund loss came from here, so this is a
  known unmodelled surface, not an empty one.
- **The accumulator.** `[ACC]` has no model yet; Phase B ships one with it, and its arrival will
  change `reorg`'s guarantees, because reorgs mutate `A_h`.
- **Fee economics and griefing costs.** `baserail` models the griefing *residue*; who pays is
  argued in `SPEC.md`, not checked.

---

## Why not one composed model

Attempted and rejected on measurement. Three reasons, in order of how decisive they are:

1. **The solver already loses on one model alone.** `linkage`'s induction, stated directly,
   exhausted a 4 GB heap, thrashed a 16 GB laptop, and returned a Z3 `table overflow` after 22
   minutes on a 243 GB / 64-core machine. A model whose state space is the *product* of seven is
   not a bigger version of that problem; it is a different one. The fix that worked on `linkage`
   was to make the question smaller, and composition makes it larger.
2. **The inductive results would be lost.** Seven of the suite's rows hold at **all depths**. A
   composed model would almost certainly drop to bounded checking, trading proofs for coverage —
   and the bounded checks are the weaker artifact. Merging would be a downgrade wearing the word
   "unified".
3. **Falsification would get harder, and falsification is where the value is.** Each model pairs
   its `ok` rows with rows asserting the attack **reproduces** on a variant with the rule removed
   — 21 such rows across the suite. A composed model needs a composed broken variant per rule, and
   the counterexamples come back as traces through seven subsystems, which is a much worse
   diagnostic than "the free mint fires in 3 steps".

**What this file has to earn, then**, since it is a document and documents rot: `compose-check.sh`
makes the graph mechanical. Every assumption above carries a discharger or the word `Assumed`, and
the script fails if a model's header claims an assumption this file does not list, or if this file
lists a discharger that does not exist. That is the free-mint shape — an assumption nobody owns —
turned into a build error.
