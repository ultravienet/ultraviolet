# Constraint coverage: which rules are defended by which tests

`AUDIT-BRIEF.md`'s first question to a reviewer is *"is every column constrained
on every row where it matters?"* This file is the other half of that question,
the half we can answer mechanically: **is every constraint defended by a test
that would notice if it vanished?**

The measurement is `air/mutants.py` — delete each numbered constraint, rebuild,
run the suite, record whether anything failed. It is manual (~30 min, 33 rebuild
cycles), like `formal/verify.sh`, and for the same reason. Re-run it after
touching the constraints and update the table below.

```
python3 air/mutants.py         # full sweep
python3 air/mutants.py 17      # one constraint
```

## The headline, stated plainly

**There is one circuit.** `authproto_air.rs` is the whole money path and the whole
sweep. If a second consensus circuit is ever added it must be listed in
`air/mutants.py`, or the sweep will report a full kill over half the money path.

**Latest sweep: `authproto_air.rs`, 17 mutants, 17 killed, 0 survived** (2026-07-30, subject
`60cbc596aebf5659`). **Every constraint in the money-path circuit is defended by a test that
fails if it vanishes**, up from 7 of 16.

Three numbers, and they measure different things:

| check | result | what it means |
|---|---|---|
| mutation sweep | **17 of 17 killed** | no constraint can be deleted with the tests still green |
| per-column probe | **361 of 361 columns** | no column is a free variable at *some* row |
| **pairwise probe** | **0 compensating pairs of 1,029,978** | no two cells can be moved together to cancel |

How the seventeen split, because "0 survived" is only interesting with its mechanism:

- **8 by ordinary tests** — the kernel2 negatives and the conformance replays (3, 11, 12, 14)
  and `authproto_constraints_are_isolated.rs` (2, 15, 16, **4b**). Constraint 11 joined when the
  money path cut over: the `an_honest_hop` transplant check now runs through this circuit, so a
  swapped sponge output no longer matches its pinned digest.
- **9 by the per-column probe** (`air/tests/every_column_is_constrained.rs`) — the sponge-lane
  cluster (4–10, 13) and the permutation (1). These survived for two months on an **inheritance
  argument**: the expressions were lifted verbatim from a circuit that had swept clean, so they
  were assumed sound here. That argument was never a test, and it is retired.

### Constraint 4b, and how the pairwise probe found it

**The pairwise probe was written to answer "can two cells cancel?" and its first answer was
wrong.** It reported 378 compensating pairs. Investigating them showed the cells were *not*
compensating: they were **individually unconstrained**, and the test had never checked its own
precondition — its failure message claimed "while each is caught alone" and nothing verified it.
A test that names a property must test that property; the corrected version checks each cell is
pinned alone at that row before considering the pair, and reports **0 of 1,029,978**.

What the wrong answer surfaced was real, though. Mapping every cell showed **28 free field
elements** in the honest trace, all on the single padding row: `NK`, `T` and the three amount
fields, columns 314–341. Nothing read them, so a prover could choose them.

Not a soundness hole by itself — a cell no constraint reads cannot make an invalid statement
verify — but it is exactly `[EXPORT-COL]`, which this project already found and **closed**
("a column nothing reads is a column a prover controls"). Leaving 28 more would have made that
closure false. It is also constraint 4's own argument left half-applied: 4 zeroes the padding
row's *permutation lanes* because they "would otherwise be 16 free lanes per row", and the
witness columns one block later were the same thing.

**4b closes it, and the map now reads 0 free cells of 5,776.**

**A survivor was never a redundant constraint** — it meant no test *isolated* it, so the
evidence each rule did its job was weaker than "negative tests per constraint family" made it
sound. What the sweep measures is our knowledge, not the circuit. What changed is the knowledge.

**And the sweep still cannot tell you a constraint is right.** All sixteen being load-bearing
against our tests says nothing about whether the sixteen are *sufficient*. That is the external
review's question (`spec/99 [AUDIT]`), and 0 survivors makes it more pressing rather than less:
the cheap mechanical checks are now exhausted, so what remains is the part only a human finds.

## Why the existing negative tests miss

Two distinct failure modes, both worth understanding before writing more tests.

**1. Stale dependents. One tamper, many objectors.** The negative tests change a
single cell and leave every column derived from it untouched, so the trace is
inconsistent in several ways at once and *any* constraint tying those columns can
carry the rejection. `scattering_the_walk_within_a_chain_is_rejected` swaps two
selector cells to attack constraint 10 — but leaves the `acc` column describing
the old pattern, so constraint 11 objects too, and so does constraint 4 via the
chain values. Measured: deleting **4 and 10 together** still leaves that test
passing. The test proves *something* rejects. It never proved constraint 10 does.

**2. The transcript, not the circuit.** Public values are absorbed into the
Fiat-Shamir challenger, so a test that tampers a public value after proving fails
verification for a reason no constraint was consulted about.
`tampered_tips_that_satisfy_the_key_check_are_still_rejected` modifies
`proof.tips` post-hoc; it passes identically with constraint 17 deleted. It is a
good test of *proof-to-statement binding* and not a test of constraint 17 at all.

The second mode is the more dangerous of the two, because the test reads exactly
like the thing it fails to check.

## What an isolating test looks like

Build a trace that is internally consistent — every dependent column recomputed —
and differs from an honest one in exactly the way one constraint forbids. Where
public values are involved, **prove against the lying statement** rather than
swapping it in afterwards, so the transcript is consistent and only the
constraint can object.

`air/tests/constraints_are_isolated.rs` does this, and every test in it is
verified by deleting its target and watching it fail (`python3 air/mutants.py <n>`). The forgery it
demonstrates: a trace whose chain walks end at one value, proved against public
tips declaring another. The wrapper then computes `compress(tips)` over tips the
trace never reached, and the owner-key check — the whole chain of custody — means
nothing.

## The table

`killed` = some test fails when the constraint is deleted.
`SURVIVED` = no test noticed; the constraint has no isolating evidence.

### The tables for the deleted circuits

Two earlier circuits had constraint-by-constraint sweep tables here. They are in the
[archive](https://github.com/ultravienet/ultraviolet-archive) under `deleted-circuits/`,
and the journal has why they went.

They were kept here longer than the code was, for one reason: nine of the live
circuit's constraints rested on *inheritance* from them, so the old tables were the
only evidence those nine had. **That dependency is gone** — the per-column probe closed
all nine directly on 2026-07-30. Nothing in this document rests on a circuit that does
not exist.

### `air/src/authproto_air.rs` — the proof-native transfer circuit (spec/99 `[PROOF-AUTH]`)

**The only circuit.** Authorization is the anchor constraint; there are no
signature chains. First swept 2026-07-29 at 3 killed of 16, then
`authproto_constraints_are_isolated.rs` closed the witness-column survivors, then
the per-column probe closed the sponge-lane cluster. **Now 16 killed, 0 survived**
— the headline at the top of this file, restated here because a section that
opened with a stale count ("6 killed, 10 survived") for a day is how a reader
ends up believing the wrong number.

| # | What it pins | Status |
|---|---|---|
| 1 | the Poseidon2 permutation itself | killed² |
| 2 | the vendored layout's `export` flag (column 0) | killed |
| 3 | the section register (SP) seeds at row 0 and shifts by one | killed |
| 4 | padding rows feed the permutation nothing | killed² |
| 4b | padding rows carry no witness either (`NK`, `T`, amounts) | killed |
| 5 | *(= prod 20)* a sponge starts with zeroed capacity | killed²ᵃ |
| 6 | *(= prod 21)* input length in lane 14 | killed² |
| 7 | *(= prod 22)* domain tag in lane 15 | killed² |
| 8 | *(= prod 23)* a start row's rate is its first chunk | killed² |
| 9 | *(= prod 24)* capacity carries on continuing rows | killed²ᵃ |
| 10 | *(= prod 25)* rate carry and absorb injection | killed² |
| 11 | *(= prod 26)* each sponge's final output is its public digest | killed |
| 12 | *(= prod 32)* the spend anchor opens `T` — **the authorization** | killed |
| 13 | *(= prod 27)* bus constancy across the section | killed² |
| 14 | *(= prod 28)* conservation, exact over u64 | killed |
| 15 | *(= prod 29, 30)* carries and range bits are boolean | killed |
| 16 | *(= prod 31)* limb range routing | killed |

**17 of 17 killed, 2026-07-30.** ² closed by
`air/tests/every_column_is_constrained.rs`, the per-column probe. ᵃ needed a
second attempt: the probe's first version aimed its "5/9" case at the wrong lane
and the sweep is what caught it — see below. **4b was added the same day**, by the
pairwise probe, and it is the only constraint here that came from a check rather
than from a design.

**How it got there, kept because the intermediate states were each defensible and
each wrong.** The first sweep of this circuit killed 3 of 16. The existing tests
that drive it — the native prove/verify negatives and `conformance_authorization`
— exercise exactly three properties end to end: that the anchor is the
authorization (12), that value is conserved (14), and that the sponge section is
wired up at all (3, killed because a broken seed collapses every sponge).
Everything else survived, and the argument offered for the survivors was
**inheritance**: those constraints were lifted verbatim from a circuit that had
already swept clean, so their soundness came with them.

**That argument is now retired, and it should never have been load-bearing.**
Inheritance is a claim about where an expression came from, not about whether
anything in *this* assembly would notice its absence — and "no test here notices"
is exactly what a mutation sweep measures. It was also unfalsifiable in the way
that matters: the circuit it inherited from has since been deleted, so the
evidence backing the claim left the tree while the claim stayed.

What replaced it is direct evidence, in two steps:

- **The witness-column constraints (2, 15, 16).** These live in ordinary witness
  columns — the export flag, the range bits — where one tampered cell is caught
  by exactly one constraint. `air/tests/authproto_constraints_are_isolated.rs`
  tampers each and requires refusal. 13 survivors → 10, then 9 when the
  money-path cutover routed the transplant check through this circuit.
- **The sponge-lane cluster (1, 4–10, 13).** These defend each other: each pins a
  permutation input lane, so perturbing one also trips the permutation
  constraint, and deleting the target alone still leaves the tamper caught. No
  proving-based test can separate them. `air/tests/every_column_is_constrained.rs`
  evaluates the AIR over a perturbed trace and separates failures **by which
  constraint fired**, which closes all nine — and, run over every column, shows
  361 of 361 provoke an objection, so no column is a free variable.

The gate this file used to state — *`authproto_air.rs` does not become the money
path until this table is clean* — was met on 2026-07-30 and the circuit is the
money path. The gate is kept as a standing rule for the next circuit, not as a
pending item.

## The sweep was blind to its own tests

The `2026-07-28 / 22 killed` row above was wrong, and the way it was wrong is
worth keeping. `mutants.py` ran a **hand-written list** of test targets, and
`constraints_are_isolated.rs` — the file whose entire purpose is killing these
mutants — was not in it. So the tests written to close constraints were never
consulted, the sweep reported them as survivors, and constraint 17 was recorded
as defended on the strength of running its test *directly* rather than through
the tool.

The tool now reads `air/tests/` instead of carrying a list. A list that must be
kept in step with a directory is a list that will eventually disagree with it,
and this one disagreed the first time it mattered.

## What this does not measure

Only whether *our tests* notice a deleted constraint. A constraint that is
present, defended, and **wrong** passes every line of this table — that is what
the external review is for (`spec/99 [AUDIT]`).

It also cannot find a column that **no constraint mentions at all**: deleting
nothing changes nothing, so an unconstrained column is invisible to a sweep. That
was the per-column argument, owed since the first sweep, and it is **paid** —
by evaluation rather than by proving.

## The per-column probe, and how it closes both gaps at once

`air/tests/every_column_is_constrained.rs` evaluates the AIR **concretely over
BabyBear** with a mock `AirBuilder` that records every assertion separately, by
index. That single change of instrument does what no proof-level test can:
constraint evaluation is deterministic, so assertion *k* always comes from the
same constraint, and a perturbation's failure *set* names which rules objected
where a proof would only say that one did.

The measured numbers, printed by the test so they are not folk knowledge:

| | |
|---|---|
| Permutation assertion prefix | **282** — assertions at or above this index are our own sixteen constraints, measured by running `eval_permutation` alone |
| Honest control | **6,864** assertions across the 16 rows, every one satisfied |
| Per-column result | **all 361 of 361 columns** provoke at least one constraint failure when perturbed |

**Gap one — no free variables.** Every column, perturbed on every row (two
different deltas, and both the window starting at that row and the one before it,
since constraints read `local` and `next`), provokes an objection. There is no
column a prover may choose freely. That is the property `AUDIT-BRIEF.md` §1 names
as the whole of a hand-written AIR's soundness, and it is now checked rather than
argued.

**Gap two — the nine survivors get independent evidence.** The survivors' defence
was that each pins a permutation input lane, so tampering also breaks the
permutation constraint and deleting the target leaves the tamper caught. That
excuse is now checkable: for each targeted lane the test requires a failure **at
or above index 282**, i.e. one of *our* rules firing, not the permutation
covering for it. Eight lane cases spanning constraints 4, 5, 6, 7, 8, 9, 10 and 13
all produce one.

**What the probe still cannot do**, since the point of this file is stating that:
it perturbs **one cell at a time**, so a hole needing two coordinated changes is
out of reach; and it says nothing about whether a constraint is *right*. A
constraint that is present, load-bearing, and wrong passes every line above.

### The probe's first version passed for the wrong reason

Worth keeping, because it is the same failure mode as everything else on this
page. The first version had a case labelled `"5/9: sponge capacity"` aimed at
column `1 + WIDTH - 2`, i.e. **lane 14** — which is *constraint 6's* lane, the
input length. Constraint 6 objected, the case went green, and the label claimed 5
and 9.

**Nothing in the test could have told us.** What told us was the mutation sweep:
re-run over the nine survivors, it killed seven and left **exactly 5 and 9**
alive. The two constraints the mislabelled case claimed to cover were the two
still uncovered.

Constraint 5 zeroes capacity lanes `N..WIDTH-2` on a **start** row; constraint 9
carries capacity lanes `N..WIDTH` onto a **continuing** row. Retargeted at the
first capacity lane on a start row and on a continuing row respectively, both die.

The lesson is not "check your arithmetic". It is that **the sweep and the probe
check each other**: the probe gives the sweep the isolating power it lacks, and the
sweep tells the probe when its aim is wrong. Neither alone would have caught this.
Run both.

## Ledger

**The subject, not the commit.** A sweep's result is about the constraint files
and nothing else, so that is what is identified — `./scripts/subject-hash.sh
air/src/authproto_air.rs`. This column used to hold a git
commit, which **can never resolve in this repository**: there is exactly one
commit, amended forever, and both rows below already cited hashes that no longer
existed. If the subject hash matches, an old row still describes the constraints
you are looking at; if it does not, re-run the sweep.

| Date | Subject (AIR files) | Mutants | Killed | Survived | Note |
|---|---|---|---|---|---|
| 2026-07-28 | *(pre-ledger)* | 32 | 21 | 11 | first sweep; all survivors in `wots_air.rs` |
| 2026-07-28 | *(pre-ledger)* | 32 | 22 | 10 | constraint 17 closed by an isolating test |
| 2026-07-28 | *(unverified)* | 32 | 22 | 10 | **wrong** — the sweep never ran `constraints_are_isolated`; see below |
| 2026-07-28 | `e516244cae405bf5` | 32 | 25 | 7 | tool fixed; 7, 13, 14 closed; 17 confirmed |
| 2026-07-28 | *(void)* | 31 | 25 | 6 | **do not read this row as a result** — swept a source that was already mutated; see below |
| 2026-07-28 | `e516244cae405bf5` | 32 | 25 | 7 | re-run clean after the tool fix; reproduces the row above the void one |
| 2026-07-29 | `5b08fd2ead609310` (authproto) | 16 | 3 | 13 | `authproto_air.rs` marked & first-swept; 13 survivors = isolating tests not yet ported from `transfer_air`; **gate before the money-path cutover** |
| 2026-07-29 | `5b08fd2ead609310` (authproto) | 16 | 6 | 10 | same subject, better coverage: `authproto_constraints_are_isolated.rs` closed 2/15/16 (targeted re-sweep, 3/3 killed); sponge-lane cluster (4–11, 13) + permutation (1) remain — need the mock probe |
| 2026-07-29 | `29ce49affacb9931` (authproto) | 16 | 7 | 9 | **WOTS+ circuits deleted; authproto is the only circuit.** Constraint 11 now killed — the money-path cutover routes the kernel2 `an_honest_hop` transplant check through this circuit. Survivors 1, 4–10, 13 (sponge-lane cluster + permutation), soundness inherited from the swept-clean `transfer_air` 20–32 |
| 2026-07-29 | `c21926e59faa3ead` (authproto) | 16 | 7 | 9 | **`owner_pk` dropped from the note** — 28-element preimage, 15 sponge rows, 16-row trace. The sponge tie table was re-derived from scratch; the sweep reproduces the *identical* 7 killed / 9 survived, and the differential + conformance tests pass, so the re-derivation preserved soundness |
| 2026-07-30 | `c21926e59faa3ead` (authproto) | 16 | **16** | **0** | **Every constraint defended.** The nine sponge-lane/permutation survivors closed by `air/tests/every_column_is_constrained.rs`, a per-column probe that evaluates the AIR concretely and records assertions **by index** — so a failure set names which rules objected, where a proof only says one did. The permutation's assertions are a measured prefix (282), so "our own rule fired, not the permutation covering for it" became a checkable claim. Same probe also closes the **per-column argument**: all **361 of 361** columns provoke a failure when perturbed, so no column is a free variable. Subject unchanged from the row above — the constraints did not move, the evidence did. **Two attempts:** the probe's first version aimed its 5/9 case at lane 14 (constraint 6's lane), passed for the wrong reason, and the sweep caught it by leaving exactly 5 and 9 alive. |
| 2026-07-30 | `9bcccd1036e813d7` (authproto) | 16 | **16** | **0** | **Re-run after the legacy-architecture prune, and re-run *because of the subject hash rather than in spite of it*.** The prune renamed the shared Poseidon2 module (it was still named for a deleted signature scheme), which rewrote every `wots::` path inside this circuit. No constraint, column or expression changed — but the subject hash did, and this column's stated rule is that a hash which no longer matches means re-run rather than assume. A pure identifier rename is exactly the case where assuming feels safest and where a ledger that permits assuming stops being a ledger. Identical result: 16 of 16, 0 survived. |
| 2026-07-30 | `60cbc596aebf5659` (authproto) | **17** | **17** | **0** | **A constraint was ADDED, and it is the first one this project got from a check rather than from a design.** The pairwise probe — written for blind spot BS-4, "both circuit checks perturb exactly one thing" — was run for the first time and reported 378 compensating pairs. It was **wrong**: those cells were individually unconstrained, and the test had never checked its own stated precondition. Corrected, it reports **0 of 1,029,978** pairs of individually-pinned columns, which is the real result. What the wrong answer surfaced was real: **28 free field elements** on the padding row (`NK`, `T`, the amount fields — columns 314–341), read by no constraint, i.e. `[EXPORT-COL]` again in a circuit whose closure of `[EXPORT-COL]` was on record. Constraint **4b** pins them; the cell map now reads 0 free of 5,776. |

**Not re-run for the 2026-07-28 supply change, and that is the point of the column.** That work
touched `kernel2`, `wallet2`, `btc`, `cli`, the models and the docs, and **no file in `air/src/`**.
The subject hash is still `e516244cae405bf5`, so the row above describes the constraints in front
of you exactly. A commit hash could not have told you that — every one of those commits is the
same amended commit.

### The void row, and the tool bug behind it

A sweep reported **31 mutants, 6 survivors** and looked like an ordinary result. It was
measured against `wots_air.rs` **with constraint 9 already commented out**, so every
verdict in it is worthless — including the 25 "killed", each of which was a test passing
on a circuit that was missing a rule.

What happened: an earlier run was killed by a 10-minute command timeout mid-mutation.
`mutants.py` restores in a `finally` block and its docstring claimed "restored on
interrupt", but **SIGTERM terminates CPython without unwinding** — the claim was only ever
true for Ctrl-C. Constraint 9 was left commented out in the working tree.

The second run then destroyed the evidence. Its first act was to copy each source over its
`.orig` backup, so the mutated file *became* the original and the only good copy was gone.
Nothing in the output said so; the sweep just came back one mutant smaller.

Two things make this worse than a lost half-hour, and both are why it is written up here
rather than quietly re-run:

- **The working tree held a soundness hole.** Constraint 9 (`digit` is constant down the
  chain) is what lets constraint 7's last-row check speak for every row. In a repository
  whose convention is one amended commit and a force push, a `git add -A` would have
  shipped it, and the commit it replaced would be gone.
- **A smaller number is not an obviously wrong number.** 32 → 31 and 7 → 6 both read as
  progress. Nothing distinguished the void sweep from a good one except counting the rows.

Fixed in `air/mutants.py`, in the order that matters:

1. **It refuses to start if any source already contains `// MUTANT`**, naming the files and
   the recovery command. This is the guard that survives `SIGKILL`, which no handler can
   catch — and it is what makes the other two optional rather than load-bearing.
2. `SIGTERM`/`SIGHUP`/`SIGINT` are caught and restore before exiting.
3. The `finally` path **verifies** the restore and exits non-zero if anything is still
   mutated, then says so. The failure above was invisible exactly because the tool never
   mentioned the file again.

Verified by hand-mutating a source and watching the tool refuse.

**Next, in priority order.** 13, 14 and 7 are closed — `constraints_are_isolated.rs`
now carries `shifting_chain_boundaries_is_rejected` (13),
`a_witness_inverse_that_is_not_the_inverse_is_rejected` (14, isolated via `pinv`
after a first attempt was rejected by 13 instead) and
`a_digit_that_disagrees_with_the_walk_length_is_rejected` (7).

What is left is the **chain-walk group: 2, 3, 4, 8, 9, 10 and 11**, and they are
left together on purpose. Each is a rule about how one row of a hash chain
relates to the next, and they defend each other: a trace tampered to break one
leaves a neighbouring column stale, so whichever constraint notices first does
the rejecting and the mutation survives. Deleting 4 *and* 10 together still
passes. Isolating any single one of them means building a trace that is
internally consistent under the other six — which is why **2** (booleanity) is
still the sensible start: a fractional-selector trace can be built by hand, and
that test must recompute `acc`, or 11 and 12 carry the rejection and it proves
nothing.
