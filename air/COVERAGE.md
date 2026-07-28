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

**First sweep, 2026-07-28: 32 mutants, 21 killed, 11 survived.** Every survivor
was in `wots_air.rs`. `transfer_air.rs` came through clean, which is
`sponge_lanes_are_tied.rs` earning its length.

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

`air/tests/constraints_are_isolated.rs` does this for constraint 17 and is
verified to fail when 17 is deleted (`python3 air/mutants.py 17`). The forgery it
demonstrates: a trace whose chain walks end at one value, proved against public
tips declaring another. The wrapper then computes `compress(tips)` over tips the
trace never reached, and the owner-key check — the whole chain of custody — means
nothing.

## The table

`killed` = some test fails when the constraint is deleted.
`SURVIVED` = no test noticed; the constraint has no isolating evidence.

### `air/src/wots_air.rs` — the signature section, shared by both circuits

| # | What it pins | Status |
|---|---|---|
| 1 | the Poseidon2 permutation itself | killed |
| 1b | the vendored layout's `export` flag (column 0) | killed |
| 2 | `sel` and `is_last` are boolean | **SURVIVED** |
| 3 | permutation input is the chain value, zero-padded (gated off on sponge rows) | **SURVIVED** |
| 4 | the chain advances only when selected | **SURVIVED** |
| 5 | digit bits are boolean and recompose to `digit` | killed |
| 6 | *(a binding, not an assert — enforced by 11 and 12)* | n/a |
| 7 | on a chain's last row, `acc + digit == W-1` | **SURVIVED** |
| 8 | this row's chain output is the next row's input | **SURVIVED** |
| 9 | `digit` is constant down a chain | **SURVIVED** |
| 10 | selectors are non-increasing within a chain | **SURVIVED** |
| 11 | `acc` accumulates the selectors | **SURVIVED** |
| 12 | a chain's first row starts the count at its own selector | killed |
| 13 | `pos` counts rows within a chain | **SURVIVED** |
| 14 | `is_last ⇔ pos = W-2` (inverse witness) | **SURVIVED** |
| 15 | the one-hot chain-index register `OH` | killed |
| 16 | digit binding: `digit` equals the public digit for this chain | killed |
| 17 | tip binding: a chain's last value is its public tip | killed¹ |

¹ Survived the first sweep; now killed by
`air/tests/constraints_are_isolated.rs`.

Constraints 13 and 14 deserve their own note: `AUDIT-BRIEF.md` §2 flags them as
*"That fix is young. Please attack it."* They are also survivors. A young fix
with no isolating test is the worst combination on this page, and they are the
next two to close.

### `air/src/transfer_air.rs` — the sponge section and the money rules

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

## What this does not measure

Only whether *our tests* notice a deleted constraint. A constraint that is
present, defended, and **wrong** passes every line of this table — that is what
the external review is for (`spec/99 [AUDIT]`). Nor does it find a column that
no constraint mentions at all: deleting nothing changes nothing. That gap is the
per-column argument, and it is still owed.

## Ledger

| Date | Commit | Mutants | Killed | Survived | Note |
|---|---|---|---|---|---|
| 2026-07-28 | 05497c8 | 32 | 21 | 11 | first sweep; all survivors in `wots_air.rs` |
| 2026-07-28 | 87b786a | 32 | 22 | 10 | constraint 17 closed by an isolating test |

**Next, in priority order.** Constraints **13 and 14** — `AUDIT-BRIEF.md` calls
that fix *"young. Please attack it."* and it is also unisolated, which is the
worst pair on this page. Then **7** (walk length matches digit), **10** (non-increasing selectors), and
**2** — booleanity is the cheapest to isolate, since an internally-consistent
fractional-selector trace can be built by hand.
