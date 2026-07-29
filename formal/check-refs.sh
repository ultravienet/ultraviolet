#!/usr/bin/env bash
# Every source path the formal models cite must exist.
#
# This is the rot that actually happened: after two crate renames and the zkVM
# removal, formal/ cited eight paths that were gone — including the test file
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

if [ "$FAIL" -ne 0 ]; then
  echo "a cited file or module moved or was deleted — fix the citation" >&2
  exit 1
fi
echo "all cited paths and modules exist"
