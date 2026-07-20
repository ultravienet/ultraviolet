#!/usr/bin/env bash
# Ultraviolet POC — Stage A: full Alice→Bob→Carol payment loop, fully local
# (file-backed mock chain + filesystem transport, no network). Proving is
# ~1 min/hop on a laptop CPU, so this takes a few minutes.
set -euo pipefail

UV="${UV_BIN:-./target/release/uv}"
HOME_DIR="$(mktemp -d)/uv-poc"
run() { echo "+ uv $*"; "$UV" --home "$HOME_DIR" "$@"; echo; }

echo "== data dir: $HOME_DIR =="; echo

echo "== addresses =="
run address --wallet alice
BOB=$("$UV" --home "$HOME_DIR" address --wallet bob)
CAROL=$("$UV" --home "$HOME_DIR" address --wallet carol)
echo "bob:   ${BOB:0:24}…"
echo "carol: ${CAROL:0:24}…"; echo

echo "== 1. Alice issues 1000 UVD =="
run issue --wallet alice --amount 1000
run balance --wallet alice

echo "== 2. Alice sends 300 to Bob =="
run send --wallet alice --to "$BOB" --amount 300

echo "== 3. Bob scans, verifies, ingests =="
run scan --wallet bob
run balance --wallet bob

echo "== 4. Bob sends 100 to Carol (recursion: proves on top of Alice's proof) =="
run send --wallet bob --to "$CAROL" --amount 100
run scan --wallet carol
run balance --wallet carol

echo "== 5. DOUBLE-SPEND: Alice re-spends her original note to Carol =="
run send --wallet alice --to "$CAROL" --amount 300 --allow-respend
echo "-- Carol scans the conflicting bundle; the chain's first-occurrence rejects it --"
run scan --wallet carol
run balance --wallet carol

echo "== done: Bob=700? no — Bob=200, Carol=100, double-spend rejected =="
