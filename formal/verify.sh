#!/usr/bin/env bash
# The formal verification runbook: every documented invariant, one command.
#
# **This now runs in CI on every push**, which it could not before. It was a
# manual discipline because the deep checks were slow, and the slow part was
# `channels` — its `naiveSettle` deadlock check took 45 minutes at depth 5 and
# never converged at 6. That model is gone (2026-07-28) along with its spec, and
# the suite finishes in about five minutes.
#
# Running it by hand on real hardware and recording the result in
# formal/VERIFIED.md is still worth doing; it is no longer the only thing
# standing between a regression and nobody noticing.
# CI keeps only the seconds-cheap rot checks (typecheck + reference paths);
# see .github/workflows/ci.yml.
#
# Every row carries its EXPECTED outcome, and both directions are enforced:
# an invariant that stops holding is a regression, and an attack that stops
# reproducing is one too — a model whose counterexample vanished is no longer
# modelling the risk it was written for.
#
# Bounds are the documented ones from formal/README.md, stated rather than
# rounded up. A pass here is a bounded claim at those depths, not a proof —
# except the **twelve inductive rows**, which hold at all depths:
#
#   multihop      noInflation via supplyInv
#   issuance      supplyIsKnown + assetSupplyIsKnown via supplyInv
#   authorization onlyOwnerSpends via authInv
#   reorg         acceptedStaysValid + acceptedHasLiveGenesis via reorgInv/genesisInv
#   linkage       noSplicedHistoryG via linkInv (ghost variable; see README)
#   delivery      noSettledPaymentLost via deliveryInv
#   baserail      paymentRemainsPossible via railInv (atomic) and splitInv
#                 (splitPayment), nobodyElseGetsPaid via railSafetyInv
#                 (griefable) and splitSafetyInv (splitGriefed)
#
# **Every model in the suite now has at least one all-depths proof.** The last two
# without any were `delivery` and `baserail` — the two LIVENESS models, i.e. the
# ones that say whether a payment can be made and whether a settled one can be
# taken. That was the wrong way round, and `baserail`'s own header had been
# arguing for an unbounded check since the day it was written.
#
# Each of the twelve is paired with a row asserting the induction FAILS on a
# variant that drops the rule it depends on — 12 `ok` rows, 12 `violation` rows,
# and that equality is the check. An inductive invariant that holds whether or not
# the protocol enforces its rule is proving something about the model's own
# bookkeeping, and that failure mode is silent unless it is checked for.
#
# The liveness rows additionally carry **anti-vacuity** rows, because both liveness
# properties are disjunctions and a disjunction is free if its easy term always
# holds. Those rows must VIOLATE: they exhibit a reachable state where the easy
# term does not carry the property, so the expensive conjuncts are doing work.
#
# **Why the depths differ, since they are not uniform and the reason is not the
# same in each direction:**
#
#   - For a `violation` row the depth is only a FLOOR. The row asserts an attack
#     reproduces, so the bound merely has to exceed the shortest counterexample —
#     `issuance lax` finds one in 2 steps, `byAmount` in 3. Running those to 8
#     costs solver time and proves nothing further, so they sit at 6.
#
#   - For an `ok` row the depth IS the claim. "No counterexample within 5 steps"
#     is a materially weaker statement than within 8, and the difference is not
#     cosmetic.
#
#   - 8 is the house default for `ok` rows. `multihop fixed` is deliberately at
#     10: the attack it checks the fix against is itself 8 steps, so 8 would
#     leave no headroom above the thing being defended against.
#
#   - Every remaining `ok` row is at 8 or better. The rows that sat at 5 and 6
#     were all `channels`, which could not go deeper and has been removed.
#
#   ./formal/verify.sh            # everything, cheapest models first (minutes)
#   ./formal/verify.sh multihop   # one model's rows only
set -uo pipefail
cd "$(dirname "$0")/.."

QUINT_PIN="0.32.0"
have=$(quint --version 2>/dev/null || echo "MISSING")
if [ "$have" != "$QUINT_PIN" ]; then
  echo "quint $QUINT_PIN required (found: $have) — the models were verified on it" >&2
  echo "  npm install -g @informalsystems/quint@$QUINT_PIN" >&2
  exit 1
fi

# `--count` prints the number of rows and exits, so nothing has to hand-count.
#
# **Why this exists.** The row total is quoted in `SPEC.md`, `README.md`,
# `AUDIT-BRIEF.md` and the journal, and it was wrong in all four — off by exactly
# one, because the obvious `grep -c '^run '` also matches this file's own
# `run () {` definition. That mistake shipped **twice in one day** (51-for-50,
# then 69-for-68), which makes it a tooling problem rather than a slip: a number
# a human derives by grep will eventually disagree with the runbook.
#
# The pattern below matches the row *shape* — `run <expect> ...` — so the
# function definition cannot be counted. Anything quoting the total should read
# it from here:
#
#   ./formal/verify.sh --count
if [ "${1:-}" = "--count" ]; then
  grep -cE '^run +(ok|violation) ' "$0"
  exit 0
fi

ONLY="${1:-}"
PASS=0; FAIL=0; RAN=0
declare -a FAILURES

# run <expect> <model> <main> <invariant> <max-steps> [extra flags...]
#   expect: ok | violation
run () {
  local expect="$1" model="$2" main="$3" inv="$4" steps="$5"; shift 5
  case "$ONLY" in ""|"$model") ;; *) return ;; esac
  RAN=$((RAN + 1))
  local desc="$model/$main $inv"
  local args=(verify "formal/$model.qnt" --main="$main" --invariant="$inv")
  [ "$steps" != "-" ] && args+=(--max-steps="$steps")
  args+=("$@")
  printf "%-64s expect %-9s ... " "$desc" "$expect"
  local out
  out=$(quint "${args[@]}" 2>&1)
  local got="ok"
  echo "$out" | grep -q "\[violation\]" && got="violation"
  # A crash (neither verdict) must never read as a pass.
  if ! echo "$out" | grep -qE "\[ok\]|\[violation\]"; then got="ERROR"; fi
  if [ "$got" = "$expect" ]; then
    echo "$got"
    PASS=$((PASS + 1))
  else
    echo "GOT $got  <-- REGRESSION"
    FAIL=$((FAIL + 1))
    FAILURES+=("$desc: expected $expect, got $got")
    echo "$out" | tail -5 | sed 's/^/    | /'
  fi
}

echo "== typecheck (also in CI; here so a broken model fails fast) =="
for m in formal/*.qnt; do
  printf "%-64s ... " "typecheck $m"
  if quint typecheck "$m" >/dev/null 2>&1; then echo ok; else echo FAILED; FAIL=$((FAIL+1)); fi
done
echo

# ---- cheapest models first, so a regression surfaces early ----

echo "== reorg: the confirmation policy under reorgs =="
run violation reorg shallow    acceptedStaysValid 8   # 1-conf: proven unsafe, tier withdrawn
run ok        reorg deep       acceptedStaysValid 8
run ok        reorg reconciled acceptedStaysValid 8
# All depths, and cheap (~4 s each): this model's whole space is two markers
# over five heights, so the induction is small where linkage's was not.
run ok        reorg reconciled acceptedStaysValid    -  --inductive-invariant=reorgInv
run ok        reorg reconciled acceptedHasLiveGenesis -  --inductive-invariant=genesisInv
# ...and each induction must FAIL on the variant that drops the rule it depends
# on. Added 2026-07-30: five of the six pre-existing inductive rows had no such
# pair, which was noticed only when a comment claiming they did turned out to be
# false. An inductive invariant that holds with the rule removed is proving
# something about the model, and nothing here would have said so.
run violation reorg shallow          acceptedStaysValid     -  --inductive-invariant=reorgInv
run violation reorg genesisUnchecked acceptedHasLiveGenesis -  --inductive-invariant=genesisInv
# A reorg can take the ISSUANCE and leave the spend records — or let them be
# re-mined, which is the ordinary outcome. A wallet that re-checks only
# settlement keeps coins backed by nothing findable.
run violation reorg genesisUnchecked acceptedHasLiveGenesis 8
run ok        reorg genesisChecked   acceptedHasLiveGenesis 8
echo

echo "== recursion (ACC Part 2): does a reorg strand a coin whose proof it orphaned? =="
# The design that ships makes the receiver WALK the ancestry, so a reorg is
# survivable by re-walking (reconciled, above). Recursion replaces the walk with
# one proof bound to a chain root — and a reorg below that root orphans the
# proof with no ancestry left to rebuild it. The coin is valid and unspendable.
#
# The control holds; the strict case is a LIVENESS counterexample in 3 steps,
# and it is the reason [ACC] Part 2 cannot ship without a recovery path this
# model says it lacks. Recorded in spec/99 [ACC].
run ok        reorg recursionReprovable paymentRemainsPossible 8
run violation reorg recursionStrict     paymentRemainsPossible 8
echo

echo "== privacy: what does an OBSERVER (not a thief) learn? =="
# The first model of a watcher. Two individually-harmless leaks — an on-chain
# record event and an addressed off-chain delivery — compose: an observer that
# sees both in one window pairs them and reads the payer->payee edge, amount
# still sealed. `lone` is that exposed case and MUST violate; the two
# mitigations hold. Recorded in spec/99 [FRONTRUN]/[HIDING-UNVERIFIABLE].
run violation privacy lone         unlinkable 8   # record + delivery in one window: linkable
run ok        privacy offband      unlinkable 8   # no on-chain event to pair
run ok        privacy decorrelated unlinkable 8   # events split across windows
echo

echo "== issuance: can supply change unseen? =="
run violation issuance lax      supplyIsKnown     6   # no record at all: yes, in two steps
run violation issuance byAmount supplyIsKnown     6   # matched by AMOUNT: the free mint, 3 steps
run ok        issuance strict   supplyIsKnown     8   # `SPEC.md` §9's rule, by identity: no
run ok        issuance strict   onlyMintKeyIssues 8
# Per-asset, which is what the record carrying the asset id in the clear buys.
# `globalSum` is the chain-wide total the old one-way-hash record could give,
# and it hides an unpublished coin under another asset's records.
run ok        issuance strict    assetSupplyIsKnown 8
run violation issuance globalSum assetSupplyIsKnown 8
# All-depths proofs, not bounded checks: `supplyInv` is inductive under strict
# (~100 s each — the two slowest rows in the suite, and worth it: these are the
# supply claims the whole record design exists to make true).
run ok        issuance strict supplyIsKnown      -  --inductive-invariant=supplyInv
run ok        issuance strict assetSupplyIsKnown -  --inductive-invariant=supplyInv
# The falsification pairs. `byAmount` is the free mint — the gap that matching
# records by amount instead of identity opens — so this row asserts `supplyInv`
# is inductive *because* of the identity rule and not regardless of it.
run violation issuance byAmount  supplyIsKnown      -  --inductive-invariant=supplyInv
run violation issuance globalSum assetSupplyIsKnown -  --inductive-invariant=supplyInv
echo

echo "== delivery: the carrier is untrusted for funds =="
run ok        delivery keeps    noSettledPaymentLost 10  # drop/delay/dup cost time, not money
run violation delivery discards noSettledPaymentLost 8   # discard-on-transient = the ViewIncomplete loss
# ALL DEPTHS (~4 s each). The strengthening is `accepted or resendable` — the
# payment is always either already taken or still re-sendable. The property alone
# is NOT inductive: from a state where only `bundleHeld` carries it, the
# **unguarded** `drop` breaks it, and bounded checking never saw that because the
# state is unreachable under `keeps`.
run ok        delivery keeps    noSettledPaymentLost -  --inductive-invariant=deliveryInv
# ...and it must fail under `discards`, which is unusually direct here: the
# discard branch sets `resendable' = false` with `accepted` still false, i.e. the
# exact negation of the invariant in one step.
run violation delivery discards noSettledPaymentLost -  --inductive-invariant=deliveryInv
echo

echo "== authorization: proof-native spend auth =="
run ok        authorization enforced   onlyOwnerSpends 8   # anchor preimage: only the owner spends
run ok        authorization enforced   ownerCanSpend   8   # ...and the owner is not locked out
run violation authorization anchorOnly onlyOwnerSpends 6   # public-anchor-only: the forger steals
# All depths: the authorization claim is inductive, not merely unviolated to 8.
run ok        authorization enforced onlyOwnerSpends -  --inductive-invariant=authInv
# Without the preimage requirement, the induction fails: `authInv` proves the
# spend rule, not the model's arithmetic.
run violation authorization anchorOnly onlyOwnerSpends -  --inductive-invariant=authInv
echo

echo "== linkage: off-circuit ancestry linkage =="
run violation linkage unchecked noSplicedHistory 8    # fabricateHop splices a history
run ok        linkage checked   noSplicedHistory 8
# The same property restated through the ghost variable, and — first — the same
# attack pointed at it. A ghost formulation that stopped catching `fabricateHop`
# would be worthless, and running only the `ok` direction would not reveal it.
run violation linkage unchecked noSplicedHistoryG 8
run ok        linkage checked   noSplicedHistoryG 8
# ALL DEPTHS, in ~16 s — where the direct encoding exhausted a 4 GB heap,
# thrashed a 16 GB laptop, and hit a Z3 `table overflow` after 22 minutes on a
# 243 GB / 64-core box. formal/README.md records what the ghost bought and what
# it costs (one well-foundedness step discharged by hand).
run ok        linkage checked   noSplicedHistoryG -  --inductive-invariant=linkInv
# ...and the induction MUST FAIL without the receiver's linkage check. This row
# is the difference between proving something about the protocol and proving
# something about bookkeeping the model does to itself.
run violation linkage unchecked noSplicedHistoryG -  --inductive-invariant=linkInv
# The ghost tracks the real hop graph, checked rather than argued. True in both
# modules: what the receiver checks decides what is ACCEPTED, not what descends.
run ok        linkage checked   ghostFaithful 8
run ok        linkage unchecked ghostFaithful 8
# Anti-vacuity: an honest receiver really does accept a note two hops deep, so
# `linksUp` is exercised where it can differ from `allProven`. If this row ever
# stops failing, the all-depths result above has become a claim about the empty
# set.
run violation linkage checked   onlyGenesisChildrenAccepted 8
echo

# onetime.qnt was retired 2026-07-29 with the signature it modelled: there is no
# longer a key that a second use discloses, so the hazard it checked is gone.
#
# The *discipline* is not gone, and that distinction cost a wrong comment here
# until 2026-07-30. `wallet2/src/signlog.rs` still refuses to re-prepare a spend
# — for idempotence rather than secrecy: a rebuilt transfer draws a fresh change
# index, so it carries a different bundle hash and races its own first record,
# and first occurrence wins. What that discipline now defends is modelled by
# baserail's `griefable`, not by a retired file. See docs/journal.html.

echo "== multihop: supply conservation across hops =="
run violation multihop buggy   noInflation 8          # the 8-step inflation attack
run ok        multihop fixed   noInflation 10
run violation multihop unbound noInflation 6          # unbound ancestry re-admits it
run ok        multihop bound   noInflation 8
# All depths, not bounded. This was the suite's first inductive row and its
# comment claimed to be the only one long after it was one of seven — the same
# staleness the dead `baserail ideal` row below records.
run ok        multihop bound   noInflation -  --inductive-invariant=supplyInv
# Dropping the ancestry bound breaks the induction, so `supplyInv` is carrying
# the conservation rule rather than restating the model's own bookkeeping.
run violation multihop unbound noInflation -  --inductive-invariant=supplyInv
echo

echo "== baserail: publication liveness, splits, the griefing residue =="
run ok        baserail atomic       paymentRemainsPossible 8
# There was a `baserail ideal` row here. **No such module exists** — it was
# renamed to `atomic`, which the line above already covers, and the dead row
# survived because nothing had run this file end to end since. `verify.sh`
# caught it the first time it was: its "a crash must never read as a pass" rule
# turned the missing module into a REGRESSION rather than a silent skip. That
# rule earned its keep. `check-refs.sh` now checks module names too, so the next
# one fails in CI in seconds instead of waiting for a manual run.
run violation baserail griefable    paymentRemainsPossible 8  # [FRONTRUN], reproduced
run ok        baserail griefable    nobodyElseGetsPaid     8  # ...and safety holds there
run violation baserail noMerge      paymentRemainsPossible 8  # why the wallet splits
run violation baserail splitRecords paymentRemainsPossible 8  # why merge needs atomicity
run ok        baserail splitPayment paymentRemainsPossible 8
run ok        baserail splitPayment nobodyElseGetsPaid     8
run ok        baserail splitGriefed nobodyElseGetsPaid     8
run violation baserail splitGriefed paymentRemainsPossible 8  # a burnt note is burnt

# ---- ALL DEPTHS, and this file asked for it ----
#
# `baserail.qnt`'s header states its technique as "deadlock-freedom, as an
# invariant with no step bound", and argues that a bounded "paid by step K"
# property "would report the simulator's choices rather than the protocol's".
# That argument was right and every row above runs at depth 8. These four rows
# are the file's own claim, honoured — the liveness models were the last two in
# the suite with no all-depths proof of any kind.
run ok        baserail atomic       paymentRemainsPossible -  --inductive-invariant=railInv
run ok        baserail splitPayment paymentRemainsPossible -  --inductive-invariant=splitInv
# Safety proved where the ADVERSARY IS ON, which is the only place it is worth
# proving: griefing destroys the payment without ever redirecting it, and that
# asymmetry is the whole thesis of this model.
run ok        baserail griefable    nobodyElseGetsPaid     -  --inductive-invariant=railSafetyInv
run ok        baserail splitGriefed nobodyElseGetsPaid     -  --inductive-invariant=splitSafetyInv

# ---- ...and each induction must FAIL where the rule it rests on is absent ----
# Keyless records admit the griefer and the payment really does become
# impossible — the [FRONTRUN] finding, now depth-free.
run violation baserail griefable    paymentRemainsPossible -  --inductive-invariant=railInv
# No merging: fails at obligation [1/3], not [2/3]. The payment is impossible
# before a single step is taken, which is a sharper statement than the bounded
# row can make — "not a race that can be lost, a payment that can never be
# attempted", exactly as the module's comment says.
run violation baserail noMerge      paymentRemainsPossible -  --inductive-invariant=railInv
# Drop the one-live-bundle discipline and two bundles over one note set can have
# their records CROSSED, so neither settles and no note is free. That is the
# state `disjointInputs` exists to exclude.
run violation baserail splitRecords paymentRemainsPossible -  --inductive-invariant=railInv
run violation baserail splitGriefed paymentRemainsPossible -  --inductive-invariant=splitInv

# ---- The safety inductions' partners, labelled as MODEL-SOUNDNESS not protocol ----
#
# Both safety proofs rest on `bundles` never shrinking, and **no protocol constant
# in this file can break safety**: the griefer is given no notes, no keys and no
# bundles, so it can destroy a payment but never redirect one. That is the model's
# thesis, and it leaves the safety inductions with nothing to falsify them — which
# would make an all-depths safety result a claim about bookkeeping.
#
# `PRUNE_SETTLED` is the switch. Turning it on garbage-collects a settled transfer
# while its first-occurrence records still name it, which is **the first attempt at
# this model**, recorded in `settle`'s comment as a mistake that produced a false
# safety violation. So these rows say something true and checkable — "the induction
# rests on retention" — rather than pretending a protocol rule is missing.
#
# They were added on 2026-07-30 after `check-refs.sh` gained a per-name pairing
# check and immediately reported `railSafetyInv` and `splitSafetyInv` as UNPAIRED.
# The totals had read 12 `ok` and 12 `violation`, which looks like proof of pairing:
# one invariant had three partners, exactly masking two invariants with none.
run violation baserail railPruned   nobodyElseGetsPaid 8
run violation baserail splitPruned  nobodyElseGetsPaid 8
run violation baserail railPruned   nobodyElseGetsPaid -  --inductive-invariant=railSafetyInv
run violation baserail splitPruned  nobodyElseGetsPaid -  --inductive-invariant=splitSafetyInv

# ---- Anti-vacuity: are these proofs FREE? ----
#
# `paymentRemainsPossible` is a disjunction (rail) and a three-term sum (split).
# If the easy term always carried it, the conjuncts that cost the work would be
# provably idle and the all-depths rows above would be about nothing. Each row
# here must VIOLATE, i.e. a reachable state must exist where the easy term does
# NOT carry the property.
run violation baserail atomic       fundableOrPaid          8
run violation baserail splitPayment fullyFundedFromNotes    8
# And the payment must complete: "always possible, never done" satisfies
# deadlock-freedom and is not a payment.
run violation baserail atomic       neverPaid               8
# **The sharpest row in this file.** A part must actually arrive while the
# payment is still incomplete. If this stops failing, `split` has stopped
# modelling a split and is modelling one atomic payment under another name —
# and CLAIMS.md L4 ("a payment larger than any single note remains possible")
# would have no model behind it.
run violation baserail splitPayment deliveryIsAllOrNothing  8
echo

# `channels` was here: 27 checks, the largest model in this suite, all of it
# about dispute rules for code that does not exist. Removed 2026-07-28 along
# with the chapter that specified it — see the journal. It was also the whole
# reason this runbook took hours: `naiveSettle` alone ran ~45 minutes at depth 5
# and never converged at 6, which is why every channels row sat below the
# 8-step house bound. What is left runs in minutes and is entirely about code
# that ships.

echo "=================================================================="
echo "$RAN checks: $PASS as expected, $FAIL regressions"
if [ "$FAIL" -gt 0 ]; then
  for f in "${FAILURES[@]:-}"; do echo "  REGRESSION: $f"; done
  exit 1
fi
# The subject, not the commit: a commit hash cannot resolve in a repository
# that keeps one always-amended commit, and both ledgers were already citing
# hashes that no longer existed. What decides whether this row still describes
# the models is whether the models changed.
SUBJECT=$(./scripts/subject-hash.sh formal/*.qnt)
cat <<LEDGER

All as documented. Record it — append to formal/VERIFIED.md:
| $(date +%F) | \`$SUBJECT\` | quint $QUINT_PIN | $RAN/$RAN | $(whoami) |
LEDGER
