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
# except the six inductive rows (multihop's noInflation via supplyInv,
# issuance's two supply properties via its supplyInv, authorization's
# onlyOwnerSpends via authInv, and reorg's two claims via reorgInv/genesisInv),
# which hold at all depths.
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
# A reorg can take the ISSUANCE and leave the spend records — or let them be
# re-mined, which is the ordinary outcome. A wallet that re-checks only
# settlement keeps coins backed by nothing findable.
run violation reorg genesisUnchecked acceptedHasLiveGenesis 8
run ok        reorg genesisChecked   acceptedHasLiveGenesis 8
echo

echo "== issuance: can supply change unseen? =="
run violation issuance lax      supplyIsKnown     6   # no record at all: yes, in two steps
run violation issuance byAmount supplyIsKnown     6   # matched by AMOUNT: the free mint, 3 steps
run ok        issuance strict   supplyIsKnown     8   # spec/12's rule, by identity: no
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
echo

echo "== delivery: the carrier is untrusted for funds =="
run ok        delivery keeps    noSettledPaymentLost 10  # drop/delay/dup cost time, not money
run violation delivery discards noSettledPaymentLost 8   # discard-on-transient = the ViewIncomplete loss
echo

echo "== authorization: proof-native spend auth (the WOTS+ replacement) =="
run ok        authorization enforced   onlyOwnerSpends 8   # anchor preimage: only the owner spends
run ok        authorization enforced   ownerCanSpend   8   # ...and the owner is not locked out
run violation authorization anchorOnly onlyOwnerSpends 6   # public-anchor-only: the forger steals
# All depths: the authorization claim is inductive, not merely unviolated to 8.
run ok        authorization enforced onlyOwnerSpends -  --inductive-invariant=authInv
echo

echo "== linkage: off-circuit ancestry linkage =="
run violation linkage unchecked noSplicedHistory 8    # fabricateHop splices a history
run ok        linkage checked   noSplicedHistory 8
echo

# onetime.qnt (the WOTS+ never-re-sign discipline) was retired 2026-07-29 with
# the signature itself: proof-native authorization has no key that a second use
# discloses, so both the hazard it modelled and the replay discipline it
# validated are gone. The retirement is recorded in docs/journal.html.

echo "== multihop: supply conservation across hops =="
run violation multihop buggy   noInflation 8          # the 8-step inflation attack
run ok        multihop fixed   noInflation 10
run violation multihop unbound noInflation 6          # unbound ancestry re-admits it
run ok        multihop bound   noInflation 8
# The one all-depths proof in the suite: inductive, not bounded.
run ok        multihop bound   noInflation -  --inductive-invariant=supplyInv
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
echo

# `channels` was here: 27 checks, the largest model in this suite, all of it
# about dispute rules for code that does not exist. Removed 2026-07-28 along
# with spec/07 and the model itself — see the journal. It was also the whole
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
