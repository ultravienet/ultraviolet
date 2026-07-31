#!/usr/bin/env bash
# The claims↔model↔code matrix, integrity-checked and measured.
#
# `check-refs.sh` already proves every path CLAIMS.md cites exists. This proves
# the *matrix itself* is well-formed and reports how much of it is tied to code,
# which is the campaign's completeness number (the plan's "matrix in CI, so
# completeness is measured from here on").
#
# What FAILS the build (rot, not opinion):
#   - a claim row that is not five cells wide (a dropped or extra column), or
#   - a claim row with an empty Status cell.
# A matrix with a blank status reads as covered exactly as loudly as one that is
# filled in — the same failure mode as the free mint and the is_permanent list,
# so it is a hard error rather than a note.
#
# What is REPORTED (measured, not judged): the coverage tally. It is printed,
# not asserted against a baseline — a committed baseline is a number maintained
# by memory, and the target ("no model-only on a safety row") is not met yet, so
# asserting it would just wedge CI. The number is here to be watched as it moves.
#
# Status vocabulary (documented in CLAIMS.md, matched here):
#   verified-code            the real function is checked (Kani, or an exhaustive
#                            no-wildcard match) — the strongest tie
#   model+trace              a Rust test replays the model's own ITF against the
#                            real code; "(planned)" means intended, NOT yet tied
#   model-only               a model exists, the code is not tied to it — the
#                            [MODEL-CONFORMANCE] debt
#   test-only                code is tested, but no falsifiable model
#   assumption-bounded       a checkable STRUCTURAL half that is verified in code,
#                            plus a cryptographic hardness half that no test or
#                            model of ours can falsify
#   assumption-only          the claim IS the assumption; nothing we can write
#                            establishes it
# "code-tied" below = verified-code, or model+trace that is not "(planned)".
#
# **Why the two assumption tokens exist**, added 2026-07-30. Rows for S2 and P2
# were rewritten to explain that their structure is verified and their hardness
# is assumed — and because the classifier substring-matches, the phrase
# "(verified-code)" inside that explanation silently counted them as *fully*
# code-tied and moved the headline number from 14 to 16. That is the failure mode
# this whole file exists to prevent: a number that reads as coverage without
# being it. They are matched FIRST below, before `*verified-code*`, and counted
# in their own bucket. A hash preimage assumption is not a gap and not coverage;
# it is a third thing, and the tally now says so.
set -uo pipefail
cd "$(dirname "$0")/.."
CLAIMS=formal/CLAIMS.md

FAIL=0
total=0 tied=0 model_only=0 test_only=0 other=0 assumed=0
declare -a MODEL_ONLY_ROWS
declare -a TIED_ROWS
declare -a ASSUMED_ROWS

while IFS= read -r line; do
  # A claim row begins with | S<n> | / | L<n> | / | P<n> |.
  id=$(printf '%s' "$line" | sed -nE 's/^\| *([SLP][0-9]+) *\|.*/\1/p')
  [ -z "$id" ] && continue
  total=$((total + 1))

  # Cells between the outer pipes. A well-formed row is exactly five.
  ncells=$(printf '%s\n' "$line" | awk -F'|' '{print NF - 2}')
  status=$(printf '%s\n' "$line" | awk -F'|' '{print $(NF - 1)}' | sed -E 's/^ *//; s/ *$//')

  if [ "$ncells" -ne 5 ]; then
    echo "MALFORMED $id: expected 5 cells, got $ncells (a column was dropped or a stray | added)" >&2
    FAIL=1
    continue
  fi
  if [ -z "$status" ]; then
    echo "BLANK STATUS $id: a claim with no status reads as covered — fill it in" >&2
    FAIL=1
    continue
  fi

  case "$status" in
    # FIRST, before *verified-code*: these rows explain a verified structural half
    # inside their prose, and matching that phrase would count them as whole.
    *assumption-bounded* | *assumption-only*)
      assumed=$((assumed + 1))
      ASSUMED_ROWS+=("$id")
      ;;
    *verified-code*) tied=$((tied + 1)); TIED_ROWS+=("$id") ;;
    *model+trace*)
      case "$status" in
        *planned*) other=$((other + 1)) ;;              # intended, not yet a tie
        *) tied=$((tied + 1)); TIED_ROWS+=("$id") ;;
      esac
      ;;
    *model-only*) model_only=$((model_only + 1)); MODEL_ONLY_ROWS+=("$id") ;;
    *test-only*) test_only=$((test_only + 1)) ;;
    *) other=$((other + 1)) ;;
  esac
done <"$CLAIMS"

if [ "$total" -eq 0 ]; then
  echo "no claim rows found in $CLAIMS — the parser or the table changed" >&2
  exit 1
fi

echo "claims↔model↔code matrix: $total claims"
echo "  code-tied (verified-code | model+trace done): $tied  [${TIED_ROWS[*]:-}]"
echo "  model-only ([MODEL-CONFORMANCE] debt):        $model_only  [${MODEL_ONLY_ROWS[*]:-}]"
echo "  test-only (no falsifiable model):             $test_only"
echo "  assumption-bounded/only (NOT code-tied):      $assumed  [${ASSUMED_ROWS[*]:-}]"
echo "  other (model+test, planned, mixed):           $other"
if [ "$assumed" -gt 0 ]; then
  echo "  note: the assumption rows have a verified structural half and a"
  echo "        cryptographic half nothing here can falsify. They are counted"
  echo "        apart from code-tied ON PURPOSE — folding them in would inflate"
  echo "        the headline by rows whose hard part is an audit's job."
fi

if [ "$FAIL" -ne 0 ]; then
  echo "the matrix is malformed — a row lost a column or a status — fix CLAIMS.md" >&2
  exit 1
fi
echo "matrix well-formed: every claim has five cells and a status"
