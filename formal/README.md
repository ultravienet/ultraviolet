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

Three liveness properties are now checked, across `onetime.qnt`, `channels.qnt`, and
`baserail.qnt`. They find **four ways an honest payment can become permanently impossible** — a
frozen one-time key, a burnt nullifier, a wallet that cannot reach the amount it owes, and two
transfers whose records deadlock each other — and the last of those was not previously known. The
channel dispute machine is the one that comes out clean, and only because of a rule that had been
presented as a detail.

The distinction earns its keep because **several safety properties here are bought with
liveness**:

| Safety property | What it costs | Model |
|---|---|---|
| A WOTS+ key never signs twice | A wallet that cannot recall signing must refuse forever → live coin frozen | `onetime.qnt` |
| One immutable bundle per nullifier | A third party burns your note by pairing its `nf` with garbage | `baserail.qnt` |
| Settle only at a *retrievable, co-signed* state | Nothing — and dropping the rule *creates* a freeze | `channels.qnt` |

**Technique, and its limits.** Apalache's temporal-property support is thin, so liveness here is
checked in one of two ways, and which one is used is stated per model:

- **Deadlock-freedom** (`channels.qnt`, `baserail.qnt`) — a true invariant, no step bound: the
  system never reaches a state from which progress is *impossible*. Strictly weaker than real
  liveness, since it proves progress is possible rather than taken, but it needs no fairness
  assumption and holds at all reachable states.
- **Bounded liveness** (`onetime.qnt`) — a step counter plus "nothing is stuck at step K".
  Only sound when nothing in the model ever un-sticks the stuck thing, which is true there and
  is why the bound is honest rather than decorative.

The first attempt used bounded liveness everywhere, and in `channels.qnt` it violated in *every*
module including the fully correct one — the counterexample was a state where settlement was
enabled and simply had not been scheduled. **An invariant cannot distinguish "not yet done" from
"impossible" without fairness.** Where a bound is used, this file says so.

## The models

| Model | Asks | Safety | Liveness |
|---|---|---|---|
| `multihop.qnt` | Do per-hop settlement checks compose? | **No** — fixed, and now proven inductively at all depths | — |
| `reorg.qnt` | Is confirmation depth alone enough? | **No** at 1 conf | — |
| `linkage.qnt` | Does off-circuit linkage compose after the rewrite? | **No** unless the receiver checks | — |
| `onetime.qnt` | Can a WOTS+ key be kept single-use? | Yes, with a persisted log | **Freezes** unless the log records *what* was signed |
| `channels.qnt` | Does the spec/07 dispute machine hold? | Holds; both admitted residues reproduce | No deadlock — but only because unbacked claims are dropped |
| `baserail.qnt` | Does an honest payment always complete? | Holds everywhere | **Fails three ways** |

## `multihop.qnt` — multi-hop validity under first-occurrence records

**Question.** Is checking first-occurrence at your own hop enough to conserve supply, or does
safety require checking the whole ancestry?

**Answer: it is not enough.** The model finds an 8-step inflation attack against wallets that
each run the check correctly. **Fixed**: `wallet2/src/accept.rs` walks and checks the whole
ancestry (the zkVM-era in-kernel ancestry module went with the rewrite); the rule is normative
in `spec/03-RECORDS.md`. Reproduce:

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

## `onetime.qnt` — WOTS+ one-time keys, where safety and liveness collide

**Question.** Dropping SLH-DSA for WOTS+ means signing two different messages with one key
**reveals the private key**. Can a wallet be kept single-use, and what does that cost?

**Answer: the obvious discipline is safe and freezes live money. A third discipline is both.**

```bash
quint verify formal/onetime.qnt --main=naive   --invariant=noKeyReuse          --max-steps=8  # [violation]
quint verify formal/onetime.qnt --main=guarded --invariant=noKeyReuse          --max-steps=8  # [ok]
quint verify formal/onetime.qnt --main=guarded --invariant=eventuallySpendable --max-steps=8  # [violation]
quint verify formal/onetime.qnt --main=replay  --invariant=noKeyReuse          --max-steps=8  # [ok]
quint verify formal/onetime.qnt --main=replay  --invariant=eventuallySpendable --max-steps=8  # [ok]
```

| Discipline | `noKeyReuse` (safety) | `eventuallySpendable` (bounded liveness) |
|---|---|---|
| `naive` — trusts its own memory | **violation** | violation |
| `guarded` — persists "this key signed" | ok | **violation** |
| `replay` — persists *what* it signed | ok | ok |

**`naive`, depth 3 — total loss.** Sign note 3 for payload 20. Restore from backup: the log is
gone, and because the transfer never settled the chain still shows the note unspent, so it comes
back as spendable. Sign it again for payload 10. Two payloads, one key: **the private key is
now recoverable by anyone holding both signatures.**

**`guarded`, depth 4 — the freeze.** Sign note 2; its record never confirms. The note returns to
spendable — the trace admits either route, a reorg dropping the record or a restore rescanning the
chain, and `settled` stays empty throughout either way, so **Bitcoin still shows the coin unspent**.
The log says the key has signed. The only safe answer is to refuse, forever. The reorg route is
worth noting separately because it needs no backup restore at all: an ordinary lost race freezes
the coin.

**The fix, and why it works.** WOTS+ signing is deterministic: one key and one message produce one
signature, byte for byte. So re-signing the *identical* payload reproduces the signature that
already exists and reveals nothing new. A log recording only *that* a key signed cannot offer this;
a log recording *what* it signed can. That is the whole difference between `guarded` and `replay`.

This model depends on that determinism, so it is pinned by a test rather than a comment —
`air/src/wots.rs::signing_is_deterministic`. If signing ever became randomized (a hedged or
blinded variant), the recovery path would silently turn into key disclosure.

**Getting the property right mattered more than getting the model right.** The first version
asserted "every note the wallet holds is eventually spendable" and violated immediately — by
spending a note, restoring, and refusing to spend it again. That is not a liveness failure, that is
a wallet correctly declining to double-spend. The property had to distinguish *money legitimately
gone* from *money still on-chain and unspendable*, which is what the `settled` set does. Sharpening
it also removed a supposed requirement: nullifiers are derived deterministically, so a restored
wallet can rescan the chain for its own and learn exactly which notes settled. Persistence is
load-bearing only for the window between signing and settlement.

---

## `channels.qnt` — the dispute machine, and the claim that "phantom claims are not a freeze"

**Question.** spec/07 makes four claims about the channel dispute rules. Do they hold, and is
"phantom claims are inert, **not a freeze**" — a liveness claim defended with safety-shaped
argument — actually true?

**Answer: the spec holds as written, the never-re-sign discipline is genuinely load-bearing, and
both admitted residues reproduce.**

```bash
for m in disciplined equivocating offline eclipsed naiveSettle; do
  quint verify formal/channels.qnt --main=$m --invariant=noTheft --max-steps=6
  quint verify formal/channels.qnt --main=$m --invariant=settlementNeverDeadlocks --max-steps=6
done
```

**Depths, stated rather than rounded up.** Four modules are checked to depth 6; `naiveSettle` is
checked to **depth 5**, because its settlement rule folds over the whole claim set twice and the
depth-6 run did not converge in 45 minutes. Depth 8 exhausts Node's heap on this model at all.
Every attack below is reachable within these bounds once `closeWindow` lets the window expire in
one step instead of three — so the `[ok]` results are bounded claims at a depth exceeding all known
attacks, not proofs. `conservationAtSettlement` — settlement never ratifies a state allocating more
than the funding note — is `[ok]` in all five.

| Module | What it changes | `noTheft` | `settlementNeverDeadlocks` |
|---|---|---|---|
| `disciplined` | spec/07 as written | ok | ok |
| `equivocating` | drops never-re-sign | **violation** | ok |
| `offline` | honest party unwatched past `W` | **violation** | ok |
| `eclipsed` | honest party's storage unretrievable | **violation** | ok |
| `naiveSettle` | settles at highest *claimed*, not highest *backed* | ok | **violation** |

Read the last two columns together, because the split is the result. `offline` and `eclipsed` lose
money and **do not deadlock** — exactly as spec/07 says, they are theft, not freeze. `naiveSettle`
deadlocks and **steals nothing** — a phantom claim at an unbacked seq empties the winner set and
settlement can never fire. So "drop the unbacked claim and fall through to the next" is not a
detail; it is the entire reason a phantom is inert.

**Equivocation, and why the discipline is mandatory.** The cheater gets a second, different state
co-signed at a seq already used. The honest party's view advances to it — it looks like a normal
update — while the *earlier* same-seq state stays co-signed and claimable. At settlement both are
backed at the same seq, the tie goes to the first claim published, and the cheater published first
because the unilateral close is theirs. Under the discipline the honest party's newer state must
take a higher seq, and higher wins cleanly.

**What the adversary is handed:** close timing and state, every claim they publish, retrievability
of the honest party's state, and **tie-break priority**. That last one matters — giving the honest
party priority would have quietly deleted the equivocation attack.

**What this does not cover:** claim ordering is assumed stable within the window, which is what
spec/07's reorg margin buys. If ordering were unstable, first-claim-wins would not be well defined.
The model cannot see that failure and does not pretend to.

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

What the rewrite *did* invalidate is narrower and is now covered: it moved `check_linkage` out of
the circuit (`linkage.qnt`) and replaced SLH-DSA with WOTS+ (`onetime.qnt`). Neither model above
would have caught either, because neither was looking.

## Modelling mistakes, collected

Every one of these produced a confident-looking result that was about the model or the tooling
rather than the protocol. They are recorded because the failure mode is systematic: **a model
that fails is not automatically a finding, and a model that passes is not automatically a proof.**

1. **Handing the system the thing under test.** `multihop.qnt` treated ancestry as trusted state;
   `linkage.qnt`'s first draft let hops consume only notes their builder held. Both made the
   property true by construction, and both passed.
2. **A liveness property that is too strong.** `onetime.qnt` first counted a correctly-refused
   double-spend as a freeze. Manufactured findings are worse than none.
3. **Bounded liveness measuring the scheduler.** In `channels.qnt` the bound violated in every
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
8. **A bound shorter than the attack reports `[ok]`.** `channels.qnt` at `--max-steps=6` passed
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
