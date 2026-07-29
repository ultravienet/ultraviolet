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

**There is one circuit now.** The WOTS+ signature circuit (`wots_air.rs`) and the
signature-verifying transfer circuit (`transfer_air.rs`) were **deleted 2026-07-29**
when the money path cut over to proof-native authorization (spec/99 `[PROOF-AUTH]`).
The sweep targets `authproto_air.rs` alone. The tables for the deleted circuits are
kept below as a record of what they were, marked as history.

**Latest sweep: `authproto_air.rs`, 16 mutants, 7 killed, 9 survived.** Four killed
by the kernel2 negatives + conformance (3, 11, 12, 14), three by
`authproto_constraints_are_isolated.rs` (2, 15, 16). Constraint 11 (each sponge's output
is its public digest) joined the killed set when the money path cut over: the kernel2
`an_honest_hop` transplant check now runs through this circuit, and a swapped output no
longer matches the pinned digest. The nine survivors are the sponge-lane cluster (4–10,
13) and the permutation (1); they are byte-identical to the old `transfer_air`'s
swept-clean 20–32, so their soundness is inherited — closing them directly needs the
structural mock-builder probe ported to this circuit. See the `authproto_air.rs` table
below.

**A survivor is not a redundant constraint.** It means no test *isolates* it —
that the evidence each rule does its job was weaker than "negative tests per
constraint family" made it sound. The constraints may all be load-bearing; what
the sweep measures is our knowledge, not the circuit.

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

### `air/src/wots_air.rs` — the signature section *(DELETED 2026-07-29; historical record)*

| # | What it pins | Status |
|---|---|---|
| 1 | the Poseidon2 permutation itself | killed |
| 1b | the vendored layout's `export` flag (column 0) | killed |
| 2 | `sel` and `is_last` are boolean | **SURVIVED** |
| 3 | permutation input is the chain value, zero-padded (gated off on sponge rows) | **SURVIVED** |
| 4 | the chain advances only when selected | **SURVIVED** |
| 5 | digit bits are boolean and recompose to `digit` | killed |
| 6 | *(a binding, not an assert — enforced by 11 and 12)* | n/a |
| 7 | on a chain's last row, `acc + digit == W-1` | killed¹ |
| 8 | this row's chain output is the next row's input | **SURVIVED** |
| 9 | `digit` is constant down a chain | **SURVIVED** |
| 10 | selectors are non-increasing within a chain | **SURVIVED** |
| 11 | `acc` accumulates the selectors | **SURVIVED** |
| 12 | a chain's first row starts the count at its own selector | killed |
| 13 | `pos` counts rows within a chain | killed¹ |
| 14 | `is_last ⇔ pos = W-2` (inverse witness) | killed¹ |
| 15 | the one-hot chain-index register `OH` | killed |
| 16 | digit binding: `digit` equals the public digit for this chain | killed |
| 17 | tip binding: a chain's last value is its public tip | killed¹ |

¹ Survived the first sweep; now killed by
`air/tests/constraints_are_isolated.rs`.

**Constraints 13 and 14 are closed, and 14 took a second attempt.** `AUDIT-BRIEF.md`
§2 flags that fix as *"young. Please attack it."* The obvious attack — shift the
chain boundaries by shifting `pos` — is rejected, but by **constraint 13**, not
14: a shifted `pos` breaks its own counting rule before anything reaches 14.
Measured, not assumed, and the test that does it is named for what actually
rejects it. What isolates 14 is `pinv`, the witness inverse, which appears in
exactly one equation and nowhere else — so perturbing it leaves no other
constraint able to object. Deleting 14 makes `pinv` free on every row, which is
a thousand unconstrained field elements in a consensus circuit; that is the
shape `[EXPORT-COL]` already got an entry for.

**The seven that remain are one cluster, and they defend each other.** 2, 3, 4,
8, 9, 10, 11 are the chain-walk mechanics: selector booleanity, the permutation
input, the advance rule, the carry between rows, digit constancy, monotone
selectors, the step count. Perturb any one of them and the *chain values* stop
being consistent, so constraint 4 or 8 objects before the target does. Isolating
them means rebuilding the trace's Poseidon2 columns for the altered walk —
`trace::p2_columns` is `pub(crate)`, so it cannot be done from an integration
test as the others were. That is the next piece of work here, and it is a
tooling problem rather than a soundness one.

### `air/src/transfer_air.rs` — the sponge section *(DELETED 2026-07-29; historical record)*

| # | What it pins | Status |
|---|---|---|
| 18 | the section register is empty on the first row | killed |
| 19 | the section register shifts by one per transition | killed |
| 20 | a sponge starts with zeroed capacity | killed |
| 21 | ...its input length in lane 14 | killed |
| 22 | ...and its domain tag in lane 15 | killed |
| 23 | a start row's rate is its first chunk | killed |
| 24 | capacity carries untouched on continuing rows | killed |
| 25 | rate carry and absorb injection on continuing rows | killed |
| 26 | each sponge's final output is its public digest | killed |
| 27 | bus constancy across the section | killed |
| 28 | conservation, limb-wise with boolean carries | killed |
| 29 | carries are boolean | killed |
| 30 | range bits are boolean | killed |
| 31 | limb range routing | killed |
| 32 | the spend anchor opens `T` | killed |

### `air/src/authproto_air.rs` — the proof-native transfer circuit (spec/99 `[PROOF-AUTH]`)

The circuit the money path migrates onto: the sponge section verbatim, the WOTS+
chains gone, authorization carried by the anchor constraint alone. Marked and
first-swept 2026-07-29 (16 mutants, 3 killed, 13 survived); then
`air/tests/authproto_constraints_are_isolated.rs` closed the survivors that live
in ordinary witness columns. **Now 6 killed, 10 survived.**

| # | What it pins | Status |
|---|---|---|
| 1 | the Poseidon2 permutation itself | **SURVIVED** |
| 2 | the vendored layout's `export` flag (column 0) | killed |
| 3 | the section register (SP) seeds at row 0 and shifts by one | killed |
| 4 | padding rows feed the permutation nothing | **SURVIVED** |
| 5 | *(= prod 20)* a sponge starts with zeroed capacity | **SURVIVED** |
| 6 | *(= prod 21)* input length in lane 14 | **SURVIVED** |
| 7 | *(= prod 22)* domain tag in lane 15 | **SURVIVED** |
| 8 | *(= prod 23)* a start row's rate is its first chunk | **SURVIVED** |
| 9 | *(= prod 24)* capacity carries on continuing rows | **SURVIVED** |
| 10 | *(= prod 25)* rate carry and absorb injection | **SURVIVED** |
| 11 | *(= prod 26)* each sponge's final output is its public digest | killed |
| 12 | *(= prod 32)* the spend anchor opens `T` — **the authorization** | killed |
| 13 | *(= prod 27)* bus constancy across the section | **SURVIVED** |
| 14 | *(= prod 28)* conservation, exact over u64 | killed |
| 15 | *(= prod 29, 30)* carries and range bits are boolean | killed |
| 16 | *(= prod 31)* limb range routing | killed |

**What the first sweep's three killed constraints told us, and what the other
thirteen did not.** The existing kernel2 tests that drive this circuit — the
native prove/verify negatives and `conformance_authorization` — exercise exactly
three properties end to end:
that the anchor is the authorization (12, killed by the forger-refusal replay),
that value is conserved (14, killed by the inflation negative), and that the
sponge section is wired up at all (3, killed because a broken seed collapses every
sponge). Everything else survives — **not because those constraints are dead, but
because no test isolates them here.**

**Constraints 5–16 are byte-identical to `transfer_air.rs`'s 20–32**, which swept
**clean** in the row above: same expressions, same columns, same meaning, lifted
verbatim. Their soundness is inherited from constraints already proven
load-bearing; what was missing is *direct* evidence in this assembly, because the
isolating tests (`sponge_lanes_are_tied.rs`, `constraints_are_isolated.rs`)
reference `TransferAir`, not `AuthProtoAir`.

**Closed so far — the witness-column constraints.** `2`, `15` and `16` live in
ordinary witness columns (the export flag, the range bits), where a single
tampered cell is caught by exactly one constraint.
`air/tests/authproto_constraints_are_isolated.rs` tampers each on a padding or
range row and requires refusal; the sweep confirms each flips SURVIVED → killed
(`python3 air/mutants.py authproto_air 2 15 16` → 3 killed, 0 survived). That took
the count from 13 survivors to 10; the money-path cutover then closed constraint 11
(the transplant check now runs through this circuit), leaving 9.

**The nine that remain are the sponge-lane cluster (4–10, 13) and the permutation
(1), and they defend each other.** Each pins a **permutation input lane**, so
perturbing one also breaks the permutation constraint — deleting the target alone
leaves the tamper caught, exactly the mutual-defence shape the wots_air chain-walk
cluster has. Isolating them needs the structural mock-builder probe
(`sponge_lanes_are_tied.rs`'s technique: evaluate the AIR over a perturbed trace
and separate failures *by which constraint fired*, rather than proving), ported to
this circuit's tie table — the note preimage dropped `owner_pk` (28 elements over four absorb rows),
so the free-lane map differs from production's. That port is the
next piece of work here.

**This is the gate, stated once: `authproto_air.rs` does not become the money path
until this table is clean.** Marking it and running the sweep made the debt
visible; the witness-column constraints are closed; the sponge-lane probe is what
remains, and the wallet-layer cutover waits on it.

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
the external review is for (`spec/99 [AUDIT]`). Nor does it find a column that
no constraint mentions at all: deleting nothing changes nothing. That gap is the
per-column argument, and it is still owed.

## Ledger

**The subject, not the commit.** A sweep's result is about the constraint files
and nothing else, so that is what is identified — `./scripts/subject-hash.sh
air/src/wots_air.rs air/src/transfer_air.rs`. This column used to hold a git
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
