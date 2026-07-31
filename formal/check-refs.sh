#!/usr/bin/env bash
# Every source path the formal models cite must exist.
#
# This is the rot that actually happened: after two crate renames and a
# subsystem removal, formal/ cited eight paths that were gone — including the test file
# named twice as the real-code replay of the inflation attack. A model whose
# citations are dead is still quoted as evidence; nothing turned red. This
# does, in seconds, so it runs in CI on every push (the deep verification is
# manual — see formal/VERIFIED.md).
set -euo pipefail
cd "$(dirname "$0")/.."

FAIL=0
# Path-like tokens: at least one directory segment, a known extension.
for f in formal/*.qnt formal/*.md formal/*.sh; do
  while IFS= read -r ref; do
    if [ ! -e "$ref" ]; then
      echo "DEAD REFERENCE in $f: $ref" >&2
      FAIL=1
    fi
  done < <(grep -oE '\b[a-z0-9_.-]+(/[a-z0-9_.-]+)+\.(rs|qnt|tla|md|sh|toml)\b' "$f" \
           | grep -vE '^(target|node_modules)/' | sort -u)
done

# Every module `verify.sh` runs must exist in the model it names.
#
# Added after a full run found `baserail ideal` citing a module that had been
# renamed to `atomic`. The row had been dead for some time and nothing noticed,
# because this script checked *file* paths only and the deep run that would have
# caught it is manual and takes hours. A dead row is worse than a missing one:
# the file reads as though the case is covered.
while read -r model main; do
  [ -z "$model" ] && continue
  if ! grep -qE "^module $main \{" "formal/$model.qnt" 2>/dev/null; then
    echo "DEAD MODULE in formal/verify.sh: $model/$main" >&2
    FAIL=1
  fi
done < <(grep -E '^run +(ok|violation) ' formal/verify.sh | awk '{print $3, $4}' | sort -u)

# Every `--main=<module>` a MODEL'S OWN HEADER tells a reader to run must exist
# too.
#
# Added 2026-07-30, and the reason is uncomfortable. The check above was written
# because `verify.sh` cited `baserail ideal`, a module renamed to `atomic`. The
# fix caught the row in `verify.sh` — and missed the *identical dead reference in
# `baserail.qnt`'s own header*, which had been telling readers to run
# `--main=ideal` the whole time. A fix scoped to where a bug was found rather than
# to the bug's shape leaves the same bug in the next place it lives.
#
# A model's header is a runbook a human follows by hand, so a dead module name
# there costs someone a confusing error at a terminal instead of a red CI job.
while read -r model main; do
  [ -z "$main" ] && continue
  if ! grep -qE "^module $main \{" "formal/$model.qnt" 2>/dev/null; then
    echo "DEAD MODULE in formal/$model.qnt's own header comments: --main=$main" >&2
    FAIL=1
  fi
#
# Scoped to lines that are actually a command — i.e. containing `quint verify`.
# The first version grepped for `--main=` anywhere in the file and immediately
# flagged a *prose* sentence explaining that a line "said `--main=ideal` until
# 2026-07-30", which is history, not a runbook entry. A rot check that cannot tell
# an instruction from a description of a fixed bug punishes writing the history
# down, and this repository's whole practice is writing the history down.
done < <(for m in formal/*.qnt; do
           name=$(basename "$m" .qnt)
           grep -E 'quint +verify' "$m" \
             | grep -oE -- '--main=[a-zA-Z0-9_]+' \
             | sed "s|--main=|$name |"
         done | sort -u)

# Every inductive invariant proved by an `ok` row must also appear on a
# `violation` row.
#
# **The house rule this enforces, and why a comment was not enough.** An
# inductive invariant that holds whether or not the protocol enforces its rule is
# proving something about the model's own bookkeeping. So each `--inductive-invariant=X`
# on an `ok` row needs an `X` on a `violation` row too, against a variant that
# drops the rule.
#
# On 2026-07-30 a comment claimed all such rows were paired. They were not, and
# the same day a second version of the same mistake nearly shipped: the totals
# read **12 `ok` and 12 `violation`**, which looks like proof of pairing and is
# not. One invariant had *three* partners, which exactly masked *two* invariants
# having none. A matching count is not a matching set, and only a per-name check
# can tell the difference — which is why this is a script and no longer a
# sentence.
declare -a UNPAIRED
while read -r inv; do
  [ -z "$inv" ] && continue
  if ! grep -E '^run +violation ' formal/verify.sh | grep -q -- "--inductive-invariant=$inv\b"; then
    UNPAIRED+=("$inv")
    FAIL=1
  fi
done < <(grep -E '^run +ok ' formal/verify.sh \
         | grep -oE -- '--inductive-invariant=[a-zA-Z0-9_]+' \
         | sed 's|--inductive-invariant=||' | sort -u)

# Every quoted row total must equal what `verify.sh --count` reports.
#
# The total is quoted in four documents and was wrong in all four, twice in one
# day, both times off by exactly one — `grep -c '^run '` also matches
# `verify.sh`'s own `run () {`. A number maintained by hand across four files
# drifts; this makes the drift a build error instead of something a reader
# discovers.
# It asserts the CORRECT total is PRESENT, rather than hunting for wrong ones —
# and that distinction was the first version's bug. Hunting flagged
# `formal/README.md`'s "27 of 59 checks" (a dated statement about a model that
# was deleted) and every row of `formal/VERIFIED.md` (a ledger of past
# runs, whose whole purpose is to hold old numbers). Both are correct history.
#
# This is the same mistake as the first `--main=` check, which flagged a sentence
# explaining that a line *used to say* `--main=ideal`. **A rot check that cannot
# tell a current claim from a record of history punishes writing the history
# down**, and writing the history down is this repository's entire practice.
#
# Checking for presence is immune to that: old numbers may sit anywhere, but each
# of these files must contain today's.
ROWS=$(./formal/verify.sh --count)
for f in SPEC.md README.md AUDIT-BRIEF.md; do
  if ! grep -qF "$ROWS checks" "$f" 2>/dev/null; then
    echo "STALE ROW COUNT in $f: the suite has $ROWS rows and this file never says so" >&2
    echo "  Do not hand-count: \`./formal/verify.sh --count\` is the source." >&2
    FAIL=1
  fi
done

# --- "all depths" must never stand alone in an outward-facing document ---
#
# The phrase means an unbounded number of STEPS. It does not mean an unbounded
# number of notes, hops, wallets or blocks — every model reasons over a universe
# of a handful. On 2026-07-30 the phrase appeared 41 times across the repository
# and **exactly one** of those mentioned the bound.
#
# That is not a wrong claim, it is a misreadable one, which is worse: a reader,
# an auditor, or a future maintainer sees "conservation proven at all depths" and
# concludes "proven". The free mint needed two wallets and a specific routing; a
# bug needing three wallets would be invisible to these models AND covered by a
# sentence saying it was proven.
#
# So the documents a stranger reads first must qualify it near the claim.
# `formal/` may use the bare phrase freely — that is where the scope section
# lives and where the reader is already in the details.
for f in ../SPEC.md ../README.md ../AUDIT-BRIEF.md; do
  p="$(cd "$(dirname "$0")" && pwd)/$f"
  [ -f "$p" ] || continue
  if grep -q "all depths" "$p" && ! grep -qiE "universe|five-note|small world|bounded" "$p"; then
    echo "UNQUALIFIED 'all depths' in $(basename "$p")" >&2
    echo "  The phrase means unbounded STEPS, not unbounded notes/hops/wallets." >&2
    echo "  Say which universe near the claim, or a reader will read it as 'proven'." >&2
    echo "  The per-model table is in formal/README.md." >&2
    FAIL=1
  fi
done

# --- Register integrity: every bullet under a slug-bearing section has a head ---
#
# `spec/99-OPEN-PROBLEMS.md` is the single authoritative list of what is
# unfinished, and on 2026-07-30 it could not describe its own contents: **four
# bullets had lost their heads and their slugs**, leaving orphaned continuation
# lines indented under the previous entry. Four tracked problems became
# untracked, silently, and every count of open problems in the file was wrong.
# The originals were unrecoverable — one commit, amended forever, and the text
# survived nowhere else — so they are quoted verbatim under `[LOST-ENTRIES]`
# rather than invented.
#
# Nothing caught it because the existing check ran one way: *cited slug → entry
# exists*. Nothing checked *entry → well-formed*. That is the third
# one-directional check this project has been bitten by, after a claims-matrix
# row citing a test that did not exist and a conformance tie nobody recorded.
#
# So: inside the sections that carry slug bullets, a line that starts a bullet
# must carry a `[SLUG]`, and every slug in the file must be unique.
REG=../spec/99-OPEN-PROBLEMS.md
REG_PATH="$(cd "$(dirname "$0")" && pwd)/$REG"
if [ -f "$REG_PATH" ]; then
  # Bullet-style entries live under these headings; prose sections use ### heads.
  orphans=$(awk '
    /^## (Design|Watch items)/ { inlist = 1; next }
    /^## / { inlist = 0 }
    inlist && /^- / && !/\[[A-Z][A-Z0-9-]*\]/ { print FNR ": " $0 }
  ' "$REG_PATH")
  if [ -n "$orphans" ]; then
    echo "REGISTER: bullet with no [SLUG] head in spec/99-OPEN-PROBLEMS.md:" >&2
    echo "$orphans" >&2
    echo "  Every tracked problem needs a slug, or it stops being tracked." >&2
    FAIL=1
  fi
  # A continuation line directly under a section heading has lost its head.
  headless=$(awk '
    /^## (Design|Watch items)/ { inlist = 1; seen = 0; next }
    /^## / { inlist = 0 }
    inlist && /^- / { seen = 1 }
    inlist && !seen && /^  [^ ]/ { print FNR ": " $0 }
  ' "$REG_PATH")
  if [ -n "$headless" ]; then
    echo "REGISTER: orphaned continuation line (a bullet lost its head) in spec/99:" >&2
    echo "$headless" >&2
    FAIL=1
  fi
  dupes=$(grep -o '`\[[A-Z][A-Z0-9-]*\]`' "$REG_PATH" \
          | sed 's/`//g' | sort | uniq -d)
  defined=$(grep -cE '^(###|- \*\*).*`\[[A-Z][A-Z0-9-]*\]`' "$REG_PATH")
  if [ "$defined" -lt 20 ]; then
    echo "REGISTER: only $defined slug-bearing entries found — the pattern has moved" >&2
    echo "  and this check has been silently passing." >&2
    FAIL=1
  fi
  # Duplicate *definitions* (not citations) would make a slug ambiguous.
  dupdefs=$(grep -oE '^(###|- \*\*).*`\[[A-Z][A-Z0-9-]*\]`' "$REG_PATH" \
            | grep -o '`\[[A-Z][A-Z0-9-]*\]`' | sed 's/`//g' | sort | uniq -d)
  if [ -n "$dupdefs" ]; then
    echo "REGISTER: slug defined more than once: $dupdefs" >&2
    FAIL=1
  fi
  echo "  register: $defined slug-bearing entries, all headed, no duplicate slugs"
fi

if [ "${#UNPAIRED[@]}" -gt 0 ]; then
  echo "UNPAIRED INDUCTIVE INVARIANT(S) in formal/verify.sh: ${UNPAIRED[*]}" >&2
  echo "  Each is proved at all depths with nothing asserting the proof FAILS when" >&2
  echo "  the rule it rests on is removed. Add a \`run violation ... --inductive-invariant=<name>\`" >&2
  echo "  against a variant that drops that rule, or the all-depths claim may be" >&2
  echo "  about the model rather than the protocol." >&2
fi

if [ "$FAIL" -ne 0 ]; then
  echo "a cited file or module moved, was deleted, or an inductive row is unpaired" >&2
  exit 1
fi
echo "all cited paths and modules exist; every inductive invariant is paired"
