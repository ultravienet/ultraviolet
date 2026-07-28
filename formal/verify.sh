#!/usr/bin/env bash
# The formal verification runbook: every documented invariant, one command.
#
# The fast tier runs in CI on every pull request. The complete tier is manual
# and scheduled because channels' `naiveSettle` deadlock check took 45 minutes
# at depth 5 and depth 6 never converged. Complete results are recorded in
# formal/VERIFIED.md.
#
# Every row carries its EXPECTED outcome, and both directions are enforced:
# an invariant that stops holding is a regression, and an attack that stops
# reproducing is one too — a model whose counterexample vanished is no longer
# modelling the risk it was written for.
#
# Bounds are the documented ones from formal/README.md, stated rather than
# rounded up. A pass here is a bounded claim at those depths, not a proof —
# except multihop's inductive supplyInv, which holds at every transition depth
# in that model's fixed five-note universe.
#
#   ./formal/verify.sh            # everything, cheapest models first (hours)
#   ./formal/verify.sh fast       # CI tier: operational and cheap models
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

want () {
  case "$ONLY" in
    ""|"$1") return 0 ;;
    fast)
      case "$1" in
        reorg|indexer|linkage|onetime|wallet_io|baserail) return 0 ;;
        *) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

# run <expect> <model> <main> <invariant> <max-steps> [extra flags...]
#   expect: ok | violation
run () {
  local expect="$1" model="$2" main="$3" inv="$4" steps="$5"; shift 5
  want "$model" || return
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
echo

echo "== indexer: a persistent cache over a moving RPC view =="
run violation indexer midscanUnsafe noMixedSnapshot 6
run ok        indexer midscanSafe   noMixedSnapshot 8
run ok        indexer midscanSafe   answersCanonical 8
run violation indexer shortUnsafe   answersCanonical 6
run ok        indexer shortSafe     answersCanonical 8
echo

echo "== linkage: off-circuit ancestry linkage =="
run violation linkage unchecked noSplicedHistory 8    # fabricateHop splices a history
run ok        linkage checked   noSplicedHistory 8
echo

echo "== onetime: the WOTS+ never-re-sign discipline =="
run violation onetime naive   noKeyReuse          8   # naive wallet leaves the one-time regime
run ok        onetime guarded noKeyReuse          8
run violation onetime guarded eventuallySpendable 8   # ...but freezes live coin
run ok        onetime replay  noKeyReuse          8   # replay is both safe and live
run ok        onetime replay  eventuallySpendable 8
echo

echo "== wallet I/O: lock, sync, and atomic replacement =="
run violation wallet_io current        noExposedKeyReuse     8
run violation wallet_io current        publishedIsRemembered 5
run violation wallet_io current        walletFileSurvives    4
run ok        wallet_io lockedBuffered noExposedKeyReuse     8
run violation wallet_io lockedBuffered publishedIsRemembered 5
run violation wallet_io lockedBuffered walletFileSurvives    4
run ok        wallet_io lockedAtomicBuffered noExposedKeyReuse     8
run violation wallet_io lockedAtomicBuffered publishedIsRemembered 5
run ok        wallet_io lockedAtomicBuffered walletFileSurvives    8
run ok        wallet_io lockedSyncedInPlace noExposedKeyReuse     8
run violation wallet_io lockedSyncedInPlace publishedIsRemembered 8
run violation wallet_io lockedSyncedInPlace walletFileSurvives    4
run ok        wallet_io hardened       noExposedKeyReuse     10
run ok        wallet_io hardened       publishedIsRemembered 10
run ok        wallet_io hardened       walletFileSurvives    10
echo

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
run violation baserail griefable    paymentRemainsPossible 8  # [FRONTRUN], reproduced
run ok        baserail griefable    nobodyElseGetsPaid     8  # ...and safety holds there
run violation baserail noMerge      paymentRemainsPossible 8  # why the wallet splits
run violation baserail splitRecords paymentRemainsPossible 8  # why merge needs atomicity
run ok        baserail splitPayment paymentRemainsPossible 8
run ok        baserail splitPayment nobodyElseGetsPaid     8
run ok        baserail splitGriefed nobodyElseGetsPaid     8
run violation baserail splitGriefed paymentRemainsPossible 8  # a burnt note is burnt
echo

echo "== channels: bounded dispute-rule checks (SLOW — naiveSettle took ~45 min) =="
for m in disciplined equivocating offline eclipsed; do
  case "$m" in
    disciplined) run ok        channels "$m" noTheft 6 ;;
    *)           run violation channels "$m" noTheft 6 ;;  # each residue reproduces
  esac
  run ok channels "$m" settlementNeverDeadlocks 6
  run ok channels "$m" conservationAtSettlement 6
done
run ok        channels naiveSettle noTheft                  5
run violation channels naiveSettle settlementNeverDeadlocks 5  # phantom claim deadlock
run ok        channels naiveSettle conservationAtSettlement 5
echo

echo "=================================================================="
echo "$RAN checks: $PASS as expected, $FAIL regressions"
if [ "$FAIL" -gt 0 ]; then
  for f in "${FAILURES[@]:-}"; do echo "  REGRESSION: $f"; done
  exit 1
fi
cat <<LEDGER

All as documented. Record it — append to formal/VERIFIED.md:
| $(date +%F) | $(git rev-parse --short HEAD) | quint $QUINT_PIN | $RAN/$RAN | $(whoami) |
LEDGER
