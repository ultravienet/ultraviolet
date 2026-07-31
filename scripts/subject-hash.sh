#!/usr/bin/env bash
# The identity of what a manual check was run against.
#
# `air/COVERAGE.md` and `formal/VERIFIED.md` record results a human obtained by
# hand — a mutation sweep, a set of Apalache runs — and both originally logged a
# git commit alongside. **That column can never resolve here:** this repository
# keeps exactly one commit, amended forever, so every hash written down is stale
# the moment the next change lands. Both ledgers were already citing hashes that
# no longer existed.
#
# A commit was the wrong identity anyway. What decides whether an old result
# still applies is not "what else was in the tree", it is whether *the files the
# result is about* have changed. So that is what gets hashed.
#
#     ./scripts/subject-hash.sh air/src/authproto_air.rs air/src/sponge.rs
#     ./scripts/subject-hash.sh formal/*.qnt
#
# Sorted, so argument order cannot change the answer.
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$#" -gt 0 ] || { echo "usage: subject-hash.sh <file>..." >&2; exit 1; }
for f in "$@"; do
  [ -r "$f" ] || { echo "cannot read $f" >&2; exit 1; }
done

printf '%s\n' "$@" | sort | while read -r f; do
  shasum -a 256 "$f"
done | shasum -a 256 | cut -c1-16
