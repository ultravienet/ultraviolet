#!/usr/bin/env bash
# Every quoted test count must equal the number of tests that exist.
#
# This is the third time a count has drifted, and the third time it drifted the
# same way: work removed tests, four documents kept quoting the old number, and
# nothing turned red. On 2026-07-30 deleting the signature scheme took the suite
# from 224 to 217 and README, SPEC, AUDIT-BRIEF and the benchmarks page all went
# on saying 224 — in the same session that pruned dead architectures for exactly
# this reason.
#
# A count in a published document is a claim like any other. This makes it one
# the build can falsify.
#
# The count comes from `--list`, not from a run: it needs a build but no proving,
# so it is seconds rather than minutes.
#
# **`--list` counts `#[ignore]`d tests and a run does not**, which this script got
# wrong for about an hour on the day it was written. It was verified against a run
# when both said 217 — at which point the workspace had no ignored tests, so the
# two methods agreed by coincidence rather than by construction. Adding three
# ignored tests (the pairwise probe and its diagnostics, which take minutes and are
# pre-release rather than CI) made it claim 249 against a real 246.
#
# It caught itself, because the documents said 246. That is the argument for a
# check that compares two independently-derived numbers rather than asserting one:
# when they disagree, one of them is wrong, and it is not always the documents.
set -euo pipefail

cd "$(dirname "$0")/.."

# Files that quote a workspace test count. Add to this list, never remove:
# a document that stops being checked is a document that starts drifting.
FILES=(
  README.md
  SPEC.md
  AUDIT-BRIEF.md
  docs/benchmarks.html
)

echo "counting tests ..."
LISTED=$(cargo test --workspace --locked -- --list 2>/dev/null | grep -c ': test$')
IGNORED=$(cargo test --workspace --locked -- --list --ignored 2>/dev/null | grep -c ': test$')
ACTUAL=$((LISTED - IGNORED))

if [ "$ACTUAL" -lt 100 ]; then
  echo "FAIL: counted only $ACTUAL tests — that is not a plausible total, so the" >&2
  echo "      counting method has broken rather than the suite having shrunk." >&2
  echo "      Refusing to 'fix' the documents against a number this script does" >&2
  echo "      not trust." >&2
  exit 1
fi

echo "  $ACTUAL tests run ($LISTED defined, $IGNORED ignored)"

bad=0
found=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || { echo "FAIL: $f is listed here but does not exist" >&2; bad=1; continue; }
  # Any "<number> tests" in these files is a claim about the workspace suite.
  while read -r line; do
    [ -n "$line" ] || continue
    n="${line%%:*}"
    quoted=$(printf '%s' "${line#*:}" | grep -oE '[0-9]+ tests' | grep -oE '[0-9]+' | head -1)
    [ -n "$quoted" ] || continue
    found=$((found + 1))
    if [ "$quoted" != "$ACTUAL" ]; then
      echo "FAIL: $f:$n says $quoted tests; there are $ACTUAL" >&2
      bad=1
    fi
  done < <(grep -nE '[0-9]+ tests' "$f" || true)
done

if [ "$found" -eq 0 ]; then
  echo "FAIL: no quoted test count found in any of ${FILES[*]}." >&2
  echo "      Either the documents stopped stating it — in which case a reader" >&2
  echo "      has no number at all — or the pattern moved and this check has" >&2
  echo "      been silently passing. Both are failures." >&2
  exit 1
fi

[ "$bad" -eq 0 ] || exit 1
echo "$found quoted test counts, all $ACTUAL"
