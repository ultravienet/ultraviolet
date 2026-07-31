#!/usr/bin/env bash
# The composition graph, checked instead of trusted.
#
# `COMPOSITION.md` states which layer each model sits in, what each assumes, and
# who discharges it. That document is the answer to the free mint — a bug that
# lived in the *gap between* models, where each assumed the other had a rule
# covered and nothing checked the assumption had an owner.
#
# A document alone cannot answer that, because a document is exactly what was
# missing and would have rotted the same way. So this script makes three things
# hard errors:
#
#   1. **Every model appears in the graph.** Add a new `.qnt` under formal/
#      without placing it in a layer and this fails. That is the free-mint shape:
#      a model whose relationship to the others nobody wrote down.
#      (The first draft of this comment named an example filename, and
#      `check-refs.sh` immediately failed on it as a dead reference. Fair.)
#   2. **Every layer-0 assumption has an owner or says `Assumed`.** A row with a
#      blank discharger reads as covered exactly as loudly as one that is filled
#      in — the same failure mode as `claims-coverage.sh` guards in CLAIMS.md.
#   3. **Every cited discharger exists on disk.** `check-refs.sh` does this for
#      CLAIMS.md and the model files; the composition graph needs it too, or a
#      renamed test silently becomes an assumption nobody discharges.
#
# What it deliberately does NOT do: verify the composition is *correct*. That an
# assume/guarantee decomposition actually implies the whole-system property is a
# proof obligation, and it is discharged by argument in COMPOSITION.md, not here.
# This checks the graph is complete and its citations resolve.
#
#   ./formal/compose-check.sh
set -uo pipefail
cd "$(dirname "$0")/.."
DOC=formal/COMPOSITION.md
FAIL=0

[ -f "$DOC" ] || { echo "missing $DOC — the composition graph is the artifact" >&2; exit 1; }

# ---- 1. every model is placed in the LAYER DIAGRAM ----
#
# Checking for a mention anywhere in the document is not enough, and the first
# version of this script made exactly that mistake: deleting `reorg` from the
# layer table still passed, because the word `reorg` appears further down in a
# sentence about the accumulator. A passing mention is not a placement.
#
# So the check is against the fenced `layer N` diagram alone — the one place that
# states where a model sits relative to the others, which is the thing that was
# missing when the free mint slipped between two green models.
LAYERS=$(awk '/^```$/{f=!f; next} f && /layer [0-9]/' "$DOC")
if [ -z "$LAYERS" ]; then
  echo "no fenced layer diagram found in $DOC — that diagram IS the graph" >&2
  exit 1
fi

placed=0
for m in formal/*.qnt; do
  name=$(basename "$m" .qnt)
  if printf '%s' "$LAYERS" | grep -qw "$name"; then
    placed=$((placed + 1))
  else
    echo "UNPLACED MODEL: $name does not appear in the layer diagram of $DOC." >&2
    echo "  A model with no stated position relative to the others is the free-mint" >&2
    echo "  shape: it looks complete, and so does everything it silently leans on." >&2
    FAIL=1
  fi
done

# ---- 2. every layer-0 assumption has a discharger or says Assumed ----
# Rows look like:  | A1 | <assumption> | <discharger> | <claim> |
assumptions=0 assumed=0 owned=0
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -nE 's/^\| *(A[0-9]+) *\|.*/\1/p')
  [ -z "$id" ] && continue
  assumptions=$((assumptions + 1))
  disch=$(printf '%s\n' "$line" | awk -F'|' '{print $4}' | sed -E 's/^ *//; s/ *$//')
  if [ -z "$disch" ]; then
    echo "BLANK DISCHARGER $id: an assumption with no owner reads as covered." >&2
    FAIL=1
    continue
  fi
  case "$disch" in
    *Assumed*|*assumed*) assumed=$((assumed + 1)) ;;
    *) owned=$((owned + 1)) ;;
  esac
  # ---- 3. cited files must exist ----
  for path in $(printf '%s' "$disch" | grep -oE '`[a-zA-Z0-9_./-]+\.(rs|qnt|sh|md)`' | tr -d '`'); do
    if [ ! -e "$path" ]; then
      echo "DANGLING CITATION $id: $disch cites \`$path\`, which does not exist." >&2
      echo "  A renamed test silently becomes an assumption nobody discharges." >&2
      FAIL=1
    fi
  done
done <"$DOC"

if [ "$assumptions" -eq 0 ]; then
  echo "no layer-0 assumption rows found — the parser or the table changed" >&2
  exit 1
fi

echo "composition graph: $placed of $(ls formal/*.qnt | wc -l | tr -d ' ') models placed"
echo "  layer-0 assumptions: $assumptions ($owned partly discharged, $assumed frankly assumed)"

if [ "$FAIL" -ne 0 ]; then
  echo "the composition graph is incomplete — fix $DOC" >&2
  exit 1
fi
echo "every model is placed, every assumption has an owner, every citation resolves"
