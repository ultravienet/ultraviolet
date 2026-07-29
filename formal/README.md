# Formal models

Quint ([quint-lang.org](https://quint-lang.org)) models of the protocol layer, checked with
Apalache. Install: `npm install -g @informalsystems/quint`.

**Coming from TLA+?** `multihop.tla` is the actual TLA+ that Apalache runs, generated with
`quint compile --target=tlaplus`. Read it side by side with the `.qnt`. The differences that
trip people up: Quint has no `UNCHANGED`, so every variable must be assigned in every action
(hence the `x' = x` tails); `init` uses primes; `quint run` is randomized simulation while
`quint verify` is Apalache's symbolic *bounded* check, so `--max-steps=8` covers all states
reachable in 8 steps rather than a sample; and `quint typecheck` catches a class of errors TLC
would only hit at runtime.

**Scope.** These model the *protocol*: who checks what, and what an adversary can interleave.
They do **not** model cryptography — hashes, signatures, and the recursive STARK are assumed
sound and appear as primitives. A model finding is a design flaw, not a broken primitive.

## Safety and liveness

Everything here used to be a **safety** property — "nothing bad happens", checkable as an
invariant. That was not because the protocol has no liveness obligations. It was because its
liveness failures had been given safety-sounding names ("griefing", "the freeze corner") or filed
as scope limits ("no proof merging"), and then argued about with safety-shaped reasoning.

Liveness has been checked across three models, two of which are since retired — `channels.qnt`
deleted as unbuilt scope, `onetime.qnt` retired 2026-07-29 with the signature it modelled. Between
them they found **four ways an honest payment could become permanently impossible** — a frozen
one-time key, a burnt nullifier, a wallet that cannot reach the amount it owes, and two transfers
whose records deadlock each other. The first of those is not merely fixed but **structurally
gone**: proof-native authorization has no key a second use discloses, so the freeze the model
found cannot be expressed anymore. The remaining three live in `baserail.qnt`, and the last of
them was not previously known.

The distinction earns its keep because **several safety properties here are bought with
liveness**:

| Safety property | What it costs | Model |
|---|---|---|
| One immutable bundle per nullifier | A third party burns your note by pairing its `nf` with garbage | `baserail.qnt` |

The sharpest instance of the pattern used to sit above that row: "a WOTS+ key never signs twice"
was bought with "a wallet that cannot recall signing must refuse forever", freezing live coin.
That trade was not resolved but **dissolved** — the signature left the money path (2026-07-29),
and with no key to protect, nothing has to freeze to protect it.

**Technique, and its limits.** Apalache's temporal-property support is thin, so liveness here is
checked in one of two ways, and which one is used is stated per model:

- **Deadlock-freedom** (`baserail.qnt`, and formerly `channels.qnt`) — a true invariant, no step bound: the
  system never reaches a state from which progress is *impossible*. Strictly weaker than real
  liveness, since it proves progress is possible rather than taken, but it needs no fairness
  assumption and holds at all reachable states.
- **Bounded liveness** (formerly `onetime.qnt`, retired with the signature) — a step counter plus
  "nothing is stuck at step K". Only sound when nothing in the model ever un-sticks the stuck
  thing, which was true there and is why the bound was honest rather than decorative.

The first attempt used bounded liveness everywhere, and in the old `channels.qnt` it violated in *every*
module including the fully correct one — the counterexample was a state where settlement was
enabled and simply had not been scheduled. **An invariant cannot distinguish "not yet done" from
"impossible" without fairness.** Where a bound is used, this file says so.

## Below the models: proofs on the production functions (Kani)

The tier under Quint, standing since 2026-07-29: a bounded model checker (**Kani 1.29.0**,
pinned) proving properties of the *actual production Rust*, so there is no second artifact to
drift — the failure mode the free-mint bug embodied. Harnesses live in `#[cfg(kani)]` modules
beside the code they prove (`kernel2/src/{amount,digest,issuance}.rs`), run with
`cargo kani -p uv-kernel2` (~5 min), and run in CI on every push. What is proved, each for
**every** input, through the real BabyBear Montgomery arithmetic:

- every `u64` round-trips the four-limb amount codec, and `from_limbs` accepts exactly the
  canonical range — no aliased representation of any amount exists to accept;
- checked add and the transfer-shaped checked sum are exact or refuse — conservation
  arithmetic can never wrap;
- the 32-byte digest codec and the 76-byte issuance-record codec are bijective on their
  accepted domains — anything keyed by bytes on Bitcoin has exactly one byte form, so nothing
  a supply count sums can be an alias of something it already summed.

The negative control was run before trusting any of it: a deliberately false harness reports
`VERIFICATION: FAILED` loudly. The boundary is honest too — these are bit-level bounded proofs
of *functional* properties; they say nothing about the sponge, FRI, or any protocol-level
composition, which stay with the models above and the circuit discipline in `air/`.

## The models

| Model | Asks | Safety | Liveness |
|---|---|---|---|
| `multihop.qnt` | Do per-hop settlement checks compose? | **No** — fixed, and now proven inductively at all depths | — |
| `reorg.qnt` | Is confirmation depth alone enough? | **No** at 1 conf — reconciliation's two claims **inductive, all depths** | — |
| `linkage.qnt` | Does off-circuit linkage compose after the rewrite? | **No** unless the receiver checks | — |
| `authorization.qnt` | Is knowing the anchor preimage the same as being allowed to spend? | Yes — **inductive, all depths** — and binding to the *public* anchor instead is theft in 6 steps | — |
| `issuance.qnt` | Can supply change without anyone seeing? | **Yes**, two ways — both now refused, both kept as reproducing counterexamples; strict's two supply properties **inductive, all depths** | — |
| `delivery.qnt` | Can a hostile carrier cost funds? | No — but a receiver discarding on a *transient* verdict can | drop/delay/dup cost time, never money |
| `baserail.qnt` | Does an honest payment always complete? | Holds everywhere | **Fails three ways** |

`onetime.qnt` had a row here — "can a WOTS+ key be kept single-use?" — and was retired 2026-07-29
with the signature it modelled; its story is told below where its section used to be.

## `multihop.qnt` — multi-hop validity under first-occurrence records

**Question.** Is checking first-occurrence at your own hop enough to conserve supply, or does
safety require checking the whole ancestry?

**Answer: it is not enough.** The model finds an 8-step inflation attack against wallets that
each run the check correctly. **Fixed**: `wallet2/src/accept.rs` walks and checks the whole
ancestry (the zkVM-era in-kernel ancestry module went with the rewrite); the rule is normative
in `SPEC.md`. Reproduce:

```bash
quint verify formal/multihop.qnt --main=buggy --invariant=noInflation --max-steps=8
#   [violation] found a counterexample

quint verify formal/multihop.qnt --main=fixed --invariant=noInflation --max-steps=10
#   The outcome is: NoError
```

### The counterexample, in words

Mallory holds genesis note 0 and has a second wallet of her own, `mallory2`.

| Step | What happens |
|---|---|
| 1 | Build bundle 1: note 0 → `mallory2` |
| 2 | Build bundle 2: note 0 → dave. **Same input note, so the same nullifier.** |
| 3 | Publish bundle 2's record. Chain: `nf 0 → bundle 2`. **Bundle 1 has lost.** |
| 4 | `mallory2` takes note 1 from the losing bundle. It runs no check — it is the attacker's own wallet, and skipping a check breaks no rule anyone can observe. |
| 5 | Build bundle 3: note 1 → carol. Its nullifier (`1`) is fresh and uncontested. |
| 6 | Publish bundle 3's record. Chain: `nf 1 → bundle 3`. It wins. |
| 7 | **Carol accepts.** Her check passes: the first occurrence of `nf 1` is bundle 3. ✓ |
| 8 | **Dave accepts.** His check passes: the first occurrence of `nf 0` is bundle 2. ✓ |

One genesis note is now two live notes, held by two honest wallets that each verified everything
the implementation asks them to verify. Carol's money descends from a spend that lost its race,
and nothing in her possession can tell her so.

### Why the check doesn't compose

The recursive proof attests that every transition in the history was well-formed and authorized.
It cannot attest that each hop's *record* won its race, because the circuit has no view of the
chain — records are checked off-circuit, by each receiver, for their own hop only.

The tempting induction — "my sender checked their hop, so their note is good" — fails on exactly
one case: when the sender is the adversary. There is no way to verify that someone else ran a
check, so a chain of per-hop checks never composes into a statement about the whole history.

`kernel2/src/history.rs` carries a `history_digest`, but it is a rolling hash, so ancestor
nullifiers cannot be recovered from it — and at the time this model was written the bundle
transmitted only the current hop, so a receiver *could not* run the ancestry check even if it
wanted to: the data was neither derivable nor on the wire. The fix made the full lineage
travel with the payment (the `Bundle` in `cli/src/main.rs`), which is what `accept` walks.

### The same attack, against the real code

`wallet2/tests/multihop_inflation.rs` replays this trace with real kernel types
(`Note`, real nullifiers, `Record`, `bundle_hash`) against a real `Chain`.
It asserts that the own-hop check — the one the model proves insufficient —
would accept the laundered note, and that `accept`, which walks the whole
ancestry, refuses it.

No STARKs are involved, deliberately: in this attack every proof is *valid*, so
proving would add ninety minutes of CPU and test nothing. The defect is entirely
in the off-circuit acceptance predicate.

### The model's own blind spot, and what fixing it showed

The first version treated each note's `lineage` as trusted system state — the model
*handed* every note its true ancestry. Reality does not: the ancestry arrives **from the
sender**, so it is adversarial input. That single modelling choice assumed away an entire
attack, and the model would have happily certified the buggy code as correct.

The `adversarial` module lets the attacker present *any* ancestry it can assemble.
Substitution and truncation both live in that space, and the results are stark:

```bash
quint verify formal/multihop.qnt --main=unbound --invariant=noInflation --max-steps=6
#   [violation] found a counterexample          (4.8s)
quint verify formal/multihop.qnt --main=bound   --invariant=noInflation --max-steps=8
#   [ok] No violation found                     (17.7s, exhaustive to depth 8)
```

`unbound` checks that every presented hop settled but never asks whether those hops are
*this note's*. It falls over almost immediately — the attacker presents a clean list, or
simply an empty one, and "every hop settled" is vacuously true. Randomized simulation finds
it in 25ms.

`bound` adds the one thing that matters: the presented ancestry must reproduce the history
digest the verified proof committed to. That is exactly what `ancestry::verify_binding`
does by folding `advance_history_bytes` from `GENESIS_DIGEST`.

**The lesson is about modelling, not about this protocol.** A formal model is only as
honest as its choice of what the adversary controls. Ours found a real bug on day one and
was blind to a second one of the same severity, for no reason other than where we drew the
trust boundary. Worth re-asking of every model here: *what did I hand the system for free?*

### A hole the earlier draft did *not* catch

The model treats each note's `lineage` as ground truth — a state variable the
system maintains. In the real protocol the ancestry arrives **from the sender**,
so it is adversarial input, and "check that some list of hops all settled" proves
nothing: an attacker just substitutes a clean, unrelated list, or truncates the
inconvenient ancestor.

So the ancestry must be *bound* to the proof that was verified.
`ancestry::verify_binding` does this by recomputing the history-digest chain
(`advance_history_bytes` from `GENESIS_DIGEST`) and requiring it to equal the
digest the proof committed to; `wallet2/tests/multihop_inflation.rs` covers
the laundering trace itself, and `wallet2/src/accept.rs`'s linkage checks cover
substitution and truncation. The `unbound` / `bound` modules above model
exactly this distinction.

### What the fix costs

The `fixed` module checks every hop in the ancestry, and Apalache finds no violation to depth 10.
Implementing it means transmitting the ancestry — each hop's canonical transition bytes, which
derive both its nullifiers and its bundle hash — and doing one chain lookup per hop.

Cost per hop is the transition's *canonical* bytes — `40 + 32×(n_nullifiers + n_outputs)`, so
~136 B for a 1-in-2-out transfer, not the 64-byte record (a 100-hop note carries ~13 KB). Cheap in
absolute terms, but it changes a headline claim: **receiving is O(1) in proof verification and O(n) in chain lookups.** The proof
stays constant-size and still removes the need to re-verify history; what it cannot remove is the
need to confirm that history actually settled.


---

## `reorg.qnt` — does the confirmation policy survive a reorg?

**Question.** `required_confirmations` scales depth with value (1 / 3 / 6). A reorg can change
*which* record for a nullifier came first, and the wallet has no rollback. Is depth alone enough?

**Answer: not at the 1-confirmation tier.**

```bash
quint verify formal/reorg.qnt --main=shallow    --invariant=acceptedStaysValid --max-steps=7
#   [violation]  1 confirmation, no rollback, reorgs up to 2 blocks
quint verify formal/reorg.qnt --main=deep       --invariant=acceptedStaysValid --max-steps=7
#   [ok]         3 confirmations > any 2-block reorg
quint verify formal/reorg.qnt --main=reconciled --invariant=acceptedStaysValid --max-steps=7
#   [ok]         1 confirmation, but the wallet reconciles after a reorg
```

The invariant is *everything the receiver believes it owns is still the first occurrence*. It
breaks exactly where you would expect once it is written down: a payment accepted at depth 1
can be reorganized out, and without rollback the wallet never finds out. **Two independent
fixes, both proven:** wait deeper than any reorg you fear, or reconcile what you hold when the
chain changes. `required_confirmations` currently returns 1 for values under 1,000 units, so
the small-payment tier is the exposed one.

### Proving it at every depth — the inductive invariant

`--max-steps=8` proves `noInflation` for the first eight steps and says nothing about the ninth.
The model's diameter is larger than that (four builds, five records, and up to sixteen receives),
so the bounded result was genuinely incomplete. `supplyInv` closes it:

```bash
quint verify formal/multihop.qnt --main=bound --inductive-invariant=supplyInv --invariant=noInflation
#   [1/3] holds in the initial states           ✓
#   [2/3] preserved by step                     ✓
#   [3/3] implies noInflation                   ✓
#   [ok] No violation found  (56s)              — proven at ALL depths, no step bound
```

`noInflation` is not inductive by itself: it says supply is conserved without saying *why*, so
the induction step may begin in a fabricated state where an honest wallet holds a laundered note.
The strengthening supplies the structure — bundle ids unique and greater than the note they spend
(which is what makes ancestry acyclic), lineage equal to its input's lineage plus one hop, records
naming real bundles, notes actually existing, and the load-bearing clause that **honest holdings
have fully settled true ancestries**. From those, two live honest notes are impossible: each is
the end of a settled chain from note 0, `recorded` is a function so the chains coincide step for
step, one is a prefix of the other, and the shorter one's endpoint therefore has a record — it is
spent.

Two things make this more than a box-tick:

- **It fails for `unbound`, at step [2/3].** Without the digest binding, `honestHoldingsAreSettled`
  is not preserved: a receiver accepts a note whose *presented* ancestry settled while its real one
  did not. The binding is precisely what makes the induction close, which is a sharper statement
  than "we found no counterexample to depth 8".
- **The first version was inductive and useless.** Steps 1 and 2 passed; step 3 failed with a
  state containing no bundles at all, every lineage empty, and carol holding notes 3 and 4 out of
  thin air. `allHopsWin` over an empty ancestry is vacuously true, so two notes that never existed
  both counted as settled. Hence the `notesExist` clause. *An invariant can be perfectly inductive
  and still prove nothing* — only step 3 catches that.

Inductive checking also requires `typeOK`, a domain constraint on every variable. It is not a
property; Apalache needs it to construct the arbitrary states the induction step starts from, and
refuses with "bundles is used before it is assigned" without it.

### Two modelling mistakes worth recording

The first draft failed on *all three* modules identically, which looked like a devastating
protocol result and was in fact two bugs in the model:

1. **Reorg depth must be bounded against the chain's high-water mark, not the current tip.**
   Otherwise repeated shallow reorgs walk the chain backwards without limit and no confirmation
   depth is ever safe — a fact about the model, not about Bitcoin.
2. **`1.to(n)` is a *set*, and `fold` over a set has no defined order in Quint.** First
   occurrence is defined by order, so the traversal silently picked an arbitrary block as
   "first". Iterating `range(1, n+1)` as a list fixed it.

Both produced confident-looking counterexamples. A model that fails is not automatically a
finding — the first question is always whether the model is right.

---

### Proving both claims at every depth

Added 2026-07-29. `reorgInv` and `genesisInv` are inductive under `reconciled`, so the two
reorg claims stop being "no counterexample within 8 steps" and become facts at all depths:

```bash
quint verify formal/reorg.qnt --main=reconciled \
  --inductive-invariant=reorgInv   --invariant=acceptedStaysValid
quint verify formal/reorg.qnt --main=reconciled \
  --inductive-invariant=genesisInv --invariant=acceptedHasLiveGenesis
#   [ok] each, ~4 s
```

Why they are cheap where `linkage`'s was not: this model's whole space is two markers over
five heights, so the strengthening needs only the domain constraints plus the property
itself. The argument each carries: `accept` admits a marker only if it is *currently* the
first occurrence with a live genesis, `reorg` re-filters held markers in the same step it
rewrites blocks, and `mine` only appends above the tip — which can never change who was
first below it.

## `linkage.qnt` — does off-circuit linkage still compose?

**Question.** Today `check_linkage` runs *inside* the SP1 guest, so a receiver cannot skip it —
without it the proof would not exist. The sovereign-STARK rewrite drops in-circuit recursion:
each hop gets its own small proof, and the receiver verifies k of them and checks linkage
themselves. That moves linkage from *enforced by the proof* to *the receiver is supposed to do
it* — the exact shape that produced the inflation bug above. So ask before the code exists.

**Answer: it does not compose. The receiver must check, and the model says what "check" means.**

```bash
quint verify formal/linkage.qnt --main=unchecked --invariant=noSplicedHistory --max-steps=8
#   [violation]
quint verify formal/linkage.qnt --main=checked   --invariant=noSplicedHistory --max-steps=8
#   [ok] exhaustive to depth 8
```

**What the adversary controls:** the proofs, the hop sequence presented to a receiver, and — the
crucial one — the ability to build a hop consuming a note **that was never created**. A
non-recursive proof attests "this transition consumed a note with commitment X"; it says nothing
about whether X ever existed. In-circuit recursion made that unrepresentable, because the previous
proof had to exist and list X among its outputs.

**The first draft of this model passed both modules** — and was wrong. It let hops consume only
notes their builder actually held, which made every ancestry linked by construction. That is the
same error `multihop.qnt` made with ancestry: handing the system for free the very thing under
test. The `fabricateHop` action is what makes the model able to fail.

---

## `onetime.qnt` — retired 2026-07-29, with the signature it modelled

The model asked: dropping SLH-DSA for WOTS+ means signing two different messages with one key
**reveals the private key** — can a wallet be kept single-use, and what does that cost? Its answer
shaped the wallet for a month: the obvious discipline (persist "this key signed") was safe and
**froze live money** — a lost race or a backup restore left a coin Bitcoin considered unspent that
the only key could never touch again — and only a third discipline, persisting *what* was signed
so an identical payload could be replayed byte-for-byte, was both safe and live.

The migration to proof-native authorization (SPEC.md §8.4) removed the model's subject. There is
no signature on the money path, no key a second use discloses, and therefore no freeze corner and
no replay discipline to validate — proving twice reveals nothing, so re-proving is an ordinary
retry, not a recovery path walking a cliff edge. The model was deleted rather than kept as
decoration, the same judgement as `channels.qnt`: **a model of code that does not exist is a
liability wearing a credential.** Its successor for the question that remains — is anchor-preimage
knowledge the right authorization rule? — is `authorization.qnt` above, and the discipline the
wallet still needs (never two live bundles spending one note) is re-derived on its own merits in
`baserail.qnt`, no longer as a key-safety rule.

Two of its lessons outlive it, recorded in "Modelling mistakes, collected" below: a too-strong
liveness property manufactures findings, and a model resting on a code property (signing
determinism, then) should pin it with a test, not a comment.

---

## `baserail.qnt` — every honest payment eventually completes (it does not)

**Question.** The base rail needs zero liveness to *receive*. Does it need any to *pay*?

**Answer: yes, in three separate ways — and safety holds in all of them.**

```bash
quint verify formal/baserail.qnt --main=atomic       --invariant=paymentRemainsPossible --max-steps=8  # [ok]
quint verify formal/baserail.qnt --main=splitRecords --invariant=paymentRemainsPossible --max-steps=8  # [violation]
quint verify formal/baserail.qnt --main=griefable    --invariant=paymentRemainsPossible --max-steps=8  # [violation]
quint verify formal/baserail.qnt --main=noMerge      --invariant=paymentRemainsPossible --max-steps=8  # [violation]
```

`nobodyElseGetsPaid` — every first occurrence either settles one of Alice's own transfers or
destroys the note, and nothing redirects her money to anyone else — is **[ok] in all four**. That
is the point of the section. Safety is intact in exactly the runs where the money is gone.

**Griefing, depth 3.** Alice builds a transfer over notes 1 and 2 and broadcasts it, which reveals
the nullifiers. A third party publishes `nf 2 → garbage`. First occurrence wins, so note 2 is bound
forever to a hash backing no bundle: the transfer can never settle and the note can never be
respent. The griefer receives nothing. This is a **liveness** failure with no recovery path, and
"griefing" is the wrong name for it.

**No proof merging — violated at the initial state.** Alice holds 1 + 1 and owes 2, and a transfer
spends one note. There is no funding set, so nothing is enabled at all. Not a race that can be
lost; a payment that can never be attempted.

**A finding this model was not built to look for.** `splitRecords` has no griefer and no adversary
of any kind, and the payment still becomes impossible:

| Step | State |
|---|---|
| 1 | Build transfer 1 over notes {1, 2} |
| 2 | Build transfer 2 over notes {1, 2} — a rebuild after a failed broadcast is enough |
| 3 | Note 1's first occurrence names transfer **2** |
| 4 | Note 2's first occurrence names transfer **1** |

Neither can settle: settlement requires *every* input bound to that same transfer. Both notes are
consumed, nothing was paid. **One record per nullifier means a multi-input transfer settles
non-atomically** — a failure single-input transfers cannot have, because with one input the record
either lands or it does not.

This matters because merging is the obvious fix for `noMerge`, and it is not free: it must come
with either atomic multi-input settlement or a wallet discipline of never running two live
transfers over one note (`atomic`, which holds). The two liveness failures are not independent —
fixing one naively introduces the other.

---

## Re-review after the sovereign-STARK rewrite

`multihop.qnt` and `reorg.qnt` predate the rewrite. **Verdict: both remain valid, and this is
luck rather than diligence** — which is why it is written down as a checked claim.

Both abstract proofs away entirely: they model records, settlement, and confirmation depth, none
of which the rewrite touches. `multihop.qnt`'s assumption is "a verifying proof attests the
transition was well-formed and authorized, and nothing about whether ancestors' records won their
races" — as true of a hand-written AIR as of a zkVM guest. `reorg.qnt` never mentions proofs.

What the rewrite *did* invalidate is narrower and was covered at the time: it moved
`check_linkage` out of the circuit (`linkage.qnt`) and replaced SLH-DSA with WOTS+ (covered then
by `onetime.qnt`, itself since retired when the signature left the money path). Neither model
above would have caught either, because neither was looking.

### The induction that does not fit, stated as a result

`linkage.qnt` carries a strengthening (`linkInv` = `typeOK` ∧ `uniqueIds` ∧ `freshIds` ∧
`noSplicedHistory`) that **has not been proved**, and the row in `verify.sh` stays bounded at
depth 8. What was tried, so nobody repeats it:

| Attempt | Result |
|---|---|
| Default Apalache heap (4 GB) | `Ran out of heap memory` |
| 16 GB heap on a 16 GB laptop | thrashed the machine; killed |
| 64 GB heap, 243 GB / 64-core Linux box | **`table overflow` after 22 min** |

The last one is the informative one: `table overflow` is Z3 hitting an internal limit, not a
machine running out of anything. **More hardware does not fix this encoding.** The cause is
`trulyDescends`, which walks the ancestry by four nested existentials over the whole `hops`
set; under induction, where the starting state is arbitrary rather than reachable, the solver
must consider every combination the domain admits rather than the handful a real execution
builds. `uniqueIds`/`freshIds` were added to collapse that and were not enough.

The named next attempt, if someone wants it: **maintain descent as state** — a ghost set of
notes known to descend from the genesis, updated by the actions that create hops — so the
property is a set membership instead of a search. That is the standard move, and it carries the
standard hazard this file already documents twice: a ghost the actions maintain *by
construction* proves nothing, exactly like `supplyInv`'s first vacuous version. It would need
its own argument that the ghost cannot drift from the real hop graph.

Until then linkage is a bounded claim at depth 8, and the conformance tie
(`wallet2/tests/conformance_multihop.rs`, which replays the real ancestry rule against the real
`accept`) is the stronger evidence for the same rule.

## `authorization.qnt` — is knowing the preimage the same as being allowed to spend?

**Question.** Proof-native authorization replaced the signature with one rule: a spend is
authorized iff the spender exhibits the preimage of the anchor the note committed to. Is that
*rule* sound, given a sound hash?

**Answer: yes — at all depths — and the obvious weakening is theft in six steps.** The
`anchorOnly` strawman (presenting the public anchor suffices) stands in for any scheme where
authorization does not bind to a secret only the owner holds; the forger, who knows no preimage,
steals immediately. Under `enforced`, `onlyOwnerSpends` is proved **inductively** — `authInv`
adds the domain constraints and one auxiliary fact, `preimagesStayPrivate`, which is the hash
assumption carried into the induction: preimage knowledge never spreads, so the arbitrary
starting state of the induction step cannot hand the forger a secret no reachable state gives it.

```bash
quint verify formal/authorization.qnt --main=enforced   --invariant=onlyOwnerSpends --max-steps=8
quint verify formal/authorization.qnt --main=enforced   --invariant=ownerCanSpend   --max-steps=8
quint verify formal/authorization.qnt --main=anchorOnly --invariant=onlyOwnerSpends --max-steps=6
#   [violation]                       — the strawman: the forger spends a note in 6 steps
quint verify formal/authorization.qnt --main=enforced \
  --inductive-invariant=authInv --invariant=onlyOwnerSpends
#   [ok] all depths, ~0.3 s
```

`ownerCanSpend` is the liveness companion: "refuse everyone" would satisfy `onlyOwnerSpends`
vacuously. What is assumed and not modelled: the hash itself, and the Fiat–Shamir binding of a
proof to its statement — those are the circuit's job, checked by `air`'s tests, and the frozen
traces of this model drive the *real* circuit in `kernel2/tests/conformance_authorization.rs`.

## `issuance.qnt` — can supply change without anyone seeing?

**Question.** `multihop.qnt` proves supply is conserved across *transfers*, but it has no `issue`
action at all — it hardcodes one genesis note as an initial condition, so `supplyInv` says
nothing about how many genesis notes exist or who may create them. Every supply claim in this
project rested on a model in which issuance cannot happen. This is the other half.

**Answer: the rule this model was written against lost, in two steps.** With
`REQUIRE_ON_CHAIN = false` — what `wallet2::accept` did when this model found it — the model
mints without publishing and a receiver accepts it, so what a holder can spend exceeds what a
reader of Bitcoin can see. With spec/12's rule, requiring the genesis to appear in a confirmed
issuance record, `supplyIsKnown` holds. That rule has since landed: `accept` refuses a lineage
whose genesis has no confirmed record (`NoIssuanceRecord`), comparing asset id, commitment and
amount byte-for-byte, and the `lax` module is kept as the reproducing counterexample.

```bash
quint verify formal/issuance.qnt --main=lax    --invariant=supplyIsKnown --max-steps=6
#   [violation] found                — secret issuance, accepted by a receiver
quint verify formal/issuance.qnt --main=strict --invariant=supplyIsKnown --max-steps=8
#   [ok] No violation found
quint verify formal/issuance.qnt --main=strict --invariant=onlyMintKeyIssues --max-steps=8
#   [ok] No violation found          — one issuance per link of the mint chain
```

**Both supply properties are now proved at all depths (2026-07-29), not to a bound**: `supplyInv`
is an inductive invariant under `strict` — domain constraints, ids handed out in order (no
overwrite to reason about), `nextLink == idCounter`, accepted ⊆ published, records matching mints
pointwise, and the two supply properties as conjuncts.

```bash
quint verify formal/issuance.qnt --main=strict --inductive-invariant=supplyInv --invariant=supplyIsKnown
quint verify formal/issuance.qnt --main=strict --inductive-invariant=supplyInv --invariant=assetSupplyIsKnown
#   [ok] each, ~100 s — the two slowest rows in the suite
```

The strengthening earned its own counterexample on the way: without `nextLink == idCounter`
Apalache starts the induction from a state where the two have drifted apart, takes one more
issuance, and pushes `nextLink` out of its typeOK domain. The two counters move in lockstep in
every reachable state — but "reachable" is exactly what an inductive step does not get to assume,
which is the standing lesson of writing these.

**What it assumes, and where that is generous.** Signatures are sound and not modelled, so this
does not ask whether the WOTS+ mint chain is forgeable — only whether the *rules* let an unforged
issuance inflate unseen.

The `[STORAGE]` caveat that used to sit here is **gone**, and it is worth saying why rather than
deleting it silently: the record now carries the asset id and genesis commitment in the clear, so
an asset's issuances enumerate from block data and the sum is the total. While the record hashed
those fields the model was more generous than any deployment could be. `globalSum` is that old
weakness kept as a reproducing counterexample — a chain-wide check accepts an unpublished coin of
one asset under records another asset paid for.

What remains generous is narrower: nothing here models a **decoy**, a record bearing an asset id
its publisher does not own. It creates no spendable coin, so it cannot violate `supplyIsKnown`;
it inflates a reported figure, which is a reporting property this model does not state.

## Modelling mistakes, collected

> Several of these were found in models since removed — `channels.qnt` (**removed 2026-07-28**:
> dispute rules for code that does not exist, and at 27 of 59 checks the reason the runbook took
> hours rather than minutes) and `onetime.qnt` (**retired 2026-07-29** with the signature it
> modelled). The lessons they taught are kept here on purpose. A mistake does not stop being
> instructive because the file that produced it is gone, and every one of these is about *how to
> model*, not about channels or signatures.


Every one of these produced a confident-looking result that was about the model or the tooling
rather than the protocol. They are recorded because the failure mode is systematic: **a model
that fails is not automatically a finding, and a model that passes is not automatically a proof.**

1. **Handing the system the thing under test.** `multihop.qnt` treated ancestry as trusted state;
   `linkage.qnt`'s first draft let hops consume only notes their builder held. Both made the
   property true by construction, and both passed.
2. **A liveness property that is too strong.** `onetime.qnt` first counted a correctly-refused
   double-spend as a freeze. Manufactured findings are worse than none.
3. **Bounded liveness measuring the scheduler.** In the old `channels.qnt` the bound violated in every
   module, including the correct one, because nothing forced the enabled `settle` step to be taken.
   Deadlock-freedom is the right shape when there is no fairness assumption.
4. **An inductive invariant that is inductive and vacuous.** `supplyInv` passed steps 1 and 2 while
   permitting states with no bundles and notes held out of thin air. Only step 3 catches it.
5. **`oneOf` over an empty set is unconstrained, not disabled.** Apalache supplies an arbitrary
   value of the element type, so `baserail.qnt` bound nullifiers to bundles that did not exist and
   invented violations of both properties — in the module where nothing adversarial happens. Guard
   every draw from a set that a previous action populates.
6. **A deadlock is reported as a violation.** `noMerge` has nothing enabled at its initial state,
   and Apalache reports `reached a deadlock` in place of the invariant verdict — making a *safety*
   check look violated when it was never evaluated. Add a stutter action, and read the message
   text rather than grepping for `[violation]`.
7. **Do not delete `_apalache-out` while the server lives.** `quint verify` talks to a long-running
   JVM; removing its working directory makes every subsequent run fail with a missing `.smt` file,
   which looks exactly like a timeout. Kill the server, then clean.
8. **A bound shorter than the attack reports `[ok]`.** The old `channels.qnt` at `--max-steps=6` passed
   `equivocating`, which randomized simulation breaks in nine steps. A bounded `[ok]` means "not
   reachable within N", and is only evidence to the extent N exceeds the shortest attack. Fixed by
   adding a `closeWindow` step so waiting out the window costs one step instead of three — and by
   sanity-checking every expected violation with `quint run` at a *larger* bound first, which is
   cheap and catches exactly this.
9. **`timeout` does not exist on macOS.** Twenty-one verification runs "timed out" instantly.


## `split` — the wallet's answer to `noMerge`

`noMerge` violates `paymentRemainsPossible` at the *initial state*: Alice holds 1 + 1, owes 2,
a transfer takes one input, so no funding set exists and nothing is even enabled. That is a real
limitation of the circuit.

The wallet's answer is to send several single-input transfers that add up, and this module
checks that the answer works rather than leaving it as an argument in a spec file. The only
difference from `rail` is what counts as paid: the *sum* of settled transfers reaching the
target, rather than one transfer worth the target settling. Everything else — first occurrence,
the never-two-live-transfers discipline, griefing — is unchanged, because nothing else about the
protocol changes.

```
quint verify formal/baserail.qnt --main=splitPayment --invariant=paymentRemainsPossible --max-steps=8
#   [ok] No violation found          — where noMerge violates at step 0
quint verify formal/baserail.qnt --main=splitPayment --invariant=nobodyElseGetsPaid --max-steps=8
#   [ok] No violation found
quint verify formal/baserail.qnt --main=splitGriefed --invariant=nobodyElseGetsPaid --max-steps=8
#   [ok] No violation found          — safety survives the griefer
quint verify formal/baserail.qnt --main=splitGriefed --invariant=paymentRemainsPossible --max-steps=8
#   [violation] found                — and should: a burnt note is a burnt note
```

**A modelling trap this hit, recorded with the others.** The first version removed a bundle from
`bundles` when it settled, to stop its value being counted twice. That left the bundle's record
pointing at a transfer that no longer existed, and `nobodyElseGetsPaid` — which asks exactly
that question — reported a safety violation that was entirely an artifact of the model. The fix
is a `settledIds` set: a settled bundle stays, it just stops being live. **A safety result that
appears the moment you change bookkeeping is a bug in the bookkeeping until proven otherwise.**
