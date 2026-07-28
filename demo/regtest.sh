#!/usr/bin/env bash
# A real bitcoind, real reorgs, and a wallet that notices.
#
# Everything about the reorg fix is unit-tested — detection, rollback, the
# fail-open traps — but a unit test cannot tell you that Core's behaviour is
# what the code assumes. This does: it publishes a record, confirms it, then
# uses `invalidateblock` to withdraw the block underneath it, and checks the
# wallet quarantines the note instead of reporting it as fine.
#
# `invalidateblock` rather than a mining race, because a reorg you can trigger
# on demand is a reorg you can put in CI.
#
# Not run by default: it needs bitcoind. Run it by hand:
#     ./demo/regtest.sh
set -euo pipefail

BITCOIND=${BITCOIND:-bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli}
command -v "$BITCOIND" >/dev/null || { echo "SKIP: no bitcoind on PATH"; exit 0; }

DIR=$(mktemp -d)
DATA="$DIR/btc"
HOME_DIR="$DIR/uv"
mkdir -p "$DATA" "$HOME_DIR"
RPCPORT=18999
CLI="$BITCOIN_CLI -regtest -datadir=$DATA -rpcport=$RPCPORT -rpcuser=uv -rpcpassword=uv"
UV_BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/uv"
[ -x "$UV_BIN" ] || { echo "build first: cargo build --release -p uv-cli"; exit 1; }
uv () { "$UV_BIN" --home "$HOME_DIR" --backend regtest "$@"; }

# The balance's first line, WITHOUT a pipe that closes early.
#
# `uv balance | head -1` reads fine on macOS and dies on Linux: head exits after
# one line, the CLI's next println hits a closed pipe, and Rust panics on
# SIGPIPE — "failed printing to stdout: Broken pipe". Under `set -e` that takes
# the whole harness down. This is the same trap `demo/local2.sh` records, and
# adding this script to CI is what found it here: it had passed by hand on a Mac
# every time. Capture it all, then take the first line in the shell.
balance_of () {
  local all
  all=$(uv balance --wallet "$1")
  printf '%s' "${all%%$'\n'*}"
}

cleanup () {
  $CLI stop >/dev/null 2>&1 || true
  sleep 1
  rm -rf "$DIR"
}
trap cleanup EXIT

say () { printf "\n\033[1;35m== %s\033[0m\n" "$1"; }

say "starting a private regtest node"
"$BITCOIND" -regtest -datadir="$DATA" -rpcport=$RPCPORT -rpcuser=uv -rpcpassword=uv \
  -fallbackfee=0.0002 -daemon >/dev/null
for _ in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$CLI createwallet uvwallet >/dev/null 2>&1 || $CLI loadwallet uvwallet >/dev/null 2>&1 || true
ADDR=$($CLI -rpcwallet=uvwallet getnewaddress)
$CLI generatetoaddress 101 "$ADDR" >/dev/null
export UV_BTC_URL="http://127.0.0.1:$RPCPORT/wallet/uvwallet"
export UV_BTC_USER=uv UV_BTC_PASS=uv UV_PASSPHRASE=""

say "issue, pay, and confirm a record on the real chain"
# Remember the height *before* the payment: any reorg that forks below this
# orphans the record wherever it later ends up, which the second case needs and
# a naive "tip minus three" does not guarantee once the record has been
# re-mined at a new height.
BASE=$($CLI getblockcount)
uv issue --wallet alice --amount 1000 >/dev/null
uv address --wallet bob --slots 4 --out "$HOME_DIR/bob.json" >/dev/null
uv send --wallet alice --to "$HOME_DIR/bob.json" --amount 300 | grep "record published"
$CLI generatetoaddress 3 "$ADDR" >/dev/null
uv scan --wallet bob | tail -1
BEFORE=$(balance_of bob)
echo "bob holds: $BEFORE"
[ "$BEFORE" = "300" ] || { echo "FAIL: bob should hold 300 before the reorg"; exit 1; }

say "case 1: a reorg that re-mines the record — the note must SURVIVE"
# `generatetoaddress` pulls from the mempool, so an orphaned record is simply
# re-included at a new height. This is the common case, and the wallet must not
# panic and quarantine a note that is still perfectly good.
TIP=$($CLI getblockcount)
FORK=$((TIP - 3))
$CLI invalidateblock "$($CLI getblockhash $((FORK + 1)))"
# A *fresh* address, which matters more than it looks: regtest mining is
# deterministic, so generating to the same address on the same fork rebuilds
# the byte-identical block the node just marked invalid and Core refuses it
# with `duplicate-invalid`. A different coinbase makes a genuinely different
# chain.
$CLI generatetoaddress 6 "$($CLI -rpcwallet=uvwallet getnewaddress)" >/dev/null
echo "tip was $TIP, forked at $FORK, now $($CLI getblockcount) on a different chain"
uv scan --wallet bob 2>&1 | grep -E "rolled back" || true
SURVIVED=$(balance_of bob)
if [ "$SURVIVED" = "300" ]; then
  echo "VERIFIED: reorg detected, record re-mined, note correctly kept"
else
  echo "FAIL: the note was dropped ($SURVIVED) though its record was re-mined"
  exit 1
fi

say "case 2: a reorg that loses the record for good — the note must QUARANTINE"
# Same reorg, but the record does not come back: the node is restarted without
# its mempool, so the orphaned transaction is gone rather than re-included.
# This is the case the confirmation policy exists for.
TIP=$($CLI getblockcount)
# Fork below the payment itself, so the record is orphaned wherever case 1
# happened to re-mine it.
$CLI invalidateblock "$($CLI getblockhash $((BASE + 1)))"
$CLI stop >/dev/null; sleep 2
# Three things are needed to make an orphaned record actually stay gone, and
# each was discovered by watching this test fail: delete `mempool.dat` (the
# first shutdown already wrote it), start with `-persistmempool=0`, and start
# with `-walletbroadcast=0` — otherwise the node's own wallet helpfully
# re-submits the transaction it created.
rm -f "$DATA/regtest/mempool.dat"
"$BITCOIND" -regtest -datadir="$DATA" -rpcport=$RPCPORT -rpcuser=uv -rpcpassword=uv \
  -fallbackfee=0.0002 -persistmempool=0 -walletbroadcast=0 -daemon >/dev/null
for _ in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$CLI loadwallet uvwallet >/dev/null 2>&1 || true
echo "mempool after restart: $($CLI getrawmempool | tr -d '[:space:]')"
$CLI generatetoaddress 6 "$($CLI -rpcwallet=uvwallet getnewaddress)" >/dev/null
echo "forked below the payment at $BASE; tip now $($CLI getblockcount), record gone for good"

uv scan --wallet bob 2>&1 | grep -E "rolled back|quarantined|COULD NOT" || true
AFTER=$(balance_of bob)
echo "bob now holds: $AFTER"
if [ "$AFTER" = "0" ]; then
  echo "VERIFIED: the lost record was noticed and the note quarantined"
else
  echo "FAIL: bob still holds $AFTER after his record was orphaned for good"
  echo "       — this is the bug the harness exists to catch"
  exit 1
fi

say "case 3: first occurrence holds on a real chain"
# The safety half of the front-running story (spec/99 [FRONTRUN]). Records are
# keyless, so anyone can publish one — the protection is that only the *first*
# occurrence of a nullifier binds, and every later one is inert. That is what
# stops a stranger redirecting a payment; it is not what stops them destroying
# one, which is the accepted residue.
# Remembered for case 4, which has to fork below carol's payment: by the time
# it runs, that record is six blocks down and a "tip minus a few" fork leaves it
# exactly where it was.
CAROL_BASE=$($CLI getblockcount)
uv issue --wallet carol --amount 500 >/dev/null
uv address --wallet dave --slots 4 --out "$HOME_DIR/dave.json" >/dev/null
SEND=$(uv send --wallet carol --to "$HOME_DIR/dave.json" --amount 100)
VICTIM_NF=$(echo "$SEND" | awk '/record published/{print $4}')
echo "carol's nullifier: $VICTIM_NF"
$CLI generatetoaddress 3 "$($CLI -rpcwallet=uvwallet getnewaddress)" >/dev/null

# Republish the very same record. On a keyless rail anyone could do this; it
# must change nothing.
uv send --wallet carol --to "$HOME_DIR/dave.json" --amount 100 --from "$VICTIM_NF" >/dev/null 2>&1 || true
$CLI generatetoaddress 3 "$($CLI -rpcwallet=uvwallet getnewaddress)" >/dev/null

uv scan --wallet dave >/dev/null 2>&1 || true
DAVE=$(balance_of dave)
if [ "$DAVE" = "100" ]; then
  echo "VERIFIED: first occurrence bound the honest record; the duplicate was inert"
else
  echo "FAIL: dave holds '$DAVE', expected 100"; exit 1
fi

say "case 4: the same reorg, through \`uv reconcile\` rather than \`uv scan\`"
# Cases 1 and 2 reach the reorg logic through `uv scan`, which checks the
# rollback epoch and reconciles only if it moved. `uv reconcile` is a different
# entry point: a fresh chain, no epoch check, straight into the library's
# `reconcile`. Nothing covered it, and "the other command also works" is not
# something to assume about the code path a user reaches for precisely when
# they already suspect something is wrong.
#
# Stated so the comment does not overclaim: this case does NOT pin the
# `chain.refresh()` inside `reconcile`. Deleting that call leaves all four
# cases green, because `first_occurrence` on this backend brings the index to
# the tip on every single lookup — so any wallet with notes to check refreshes
# as a side effect. That call is defence for a backend whose lookups do not,
# and for a wallet with nothing to look up. Measured by deleting it, not
# assumed — and now pinned by a unit test with a purpose-built stale-view
# double: wallet2/tests/reconcile_refreshes_its_view.rs.
DAVE_BEFORE=$(balance_of dave)
[ "$DAVE_BEFORE" = "100" ] || { echo "FAIL: dave should hold 100 going in"; exit 1; }
# Fork below carol's payment, then restart without the mempool so it cannot
# come back — the same recipe case 2 needed, for the same reason.
$CLI invalidateblock "$($CLI getblockhash $((CAROL_BASE + 1)))"
$CLI stop >/dev/null; sleep 2
rm -f "$DATA/regtest/mempool.dat"
"$BITCOIND" -regtest -datadir="$DATA" -rpcport=$RPCPORT -rpcuser=uv -rpcpassword=uv \
  -fallbackfee=0.0002 -persistmempool=0 -walletbroadcast=0 -daemon >/dev/null
for _ in $(seq 1 60); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 1; done
$CLI loadwallet uvwallet >/dev/null 2>&1 || true
$CLI generatetoaddress 10 "$($CLI -rpcwallet=uvwallet getnewaddress)" >/dev/null

uv reconcile --wallet dave 2>&1 | grep -E "quarantined|COULD NOT|all held" || true
DAVE_AFTER=$(balance_of dave)
if [ "$DAVE_AFTER" = "0" ]; then
  echo "VERIFIED: \`uv reconcile\` refreshed on its own and caught the orphaned record"
else
  echo "FAIL: reconcile reports dave still holds $DAVE_AFTER against an orphaned record"
  echo "       — this is the stale-view bug the case exists to catch"
  exit 1
fi

# What this does NOT test, stated so nobody mistakes it for done: the actual
# front-running race, where a stranger's garbage record lands *first* and burns
# the payment. That needs a record published for a nullifier before the honest
# wallet's own transaction confirms, which this harness cannot yet stage
# deterministically. Still owed on spec/99 [FRONTRUN].

say "done — three reorgs and a first-occurrence check, on a real node"
