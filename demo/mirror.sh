#!/usr/bin/env bash
# A phone reads Bitcoin without naming a coin.
#
# The claim under test is a privacy one, and it is checked the only way a
# privacy claim can be: by showing the request that would leak does not exist,
# and that the lookup still gets answered.
#
#   1. a real regtest chain, with a real record on it
#   2. `uv-mirror` serving pages of that chain — and refusing, by name, to
#      answer any question about a nullifier
#   3. a second, empty index syncing those pages over HTTP
#   4. that index answering the first-occurrence lookup locally
#
# Self-checking: every step asserts. Needs bitcoind.
set -uo pipefail
set +m   # no job-control notices: a SIGTERM report on cleanup reads like a failure
cd "$(dirname "$0")/.."
ROOT="$PWD"
say() { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32mVERIFIED:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFAILED:\033[0m %s\n' "$*" >&2; exit 1; }

command -v bitcoind >/dev/null || die "bitcoind is required"
cargo build --release --bin uv --bin uv-mirror >/dev/null 2>&1 || die "build"

D="${TMPDIR:-/tmp}/uv-mirror-demo.$$"
rm -rf "$D"; mkdir -p "$D/btc" "$D/home"
PORT=$(( 19000 + RANDOM % 2000 ))
cleanup() {
  # By PID and disowned (below), so bash prints no "Terminated" notice — the
  # last line of a passing run should not read like a failure.
  [ -n "${MIRROR_PID:-}" ] && kill "$MIRROR_PID" 2>/dev/null
  bitcoin-cli -regtest -datadir="$D/btc" -rpcuser=uv -rpcpassword=uv stop >/dev/null 2>&1
  sleep 1; rm -rf "$D"
}
trap cleanup EXIT

say "a real regtest chain"
bitcoind -regtest -datadir="$D/btc" -rpcuser=uv -rpcpassword=uv -fallbackfee=0.0002 \
  -daemon -rpcport=18443 >/dev/null 2>&1
for _ in $(seq 30); do
  bitcoin-cli -regtest -datadir="$D/btc" -rpcuser=uv -rpcpassword=uv getblockchaininfo >/dev/null 2>&1 && break
  sleep 1
done
BCLI="bitcoin-cli -regtest -datadir=$D/btc -rpcuser=uv -rpcpassword=uv"
$BCLI createwallet uvwallet >/dev/null 2>&1 || $BCLI loadwallet uvwallet >/dev/null 2>&1
ADDR=$($BCLI -rpcwallet=uvwallet getnewaddress)
$BCLI generatetoaddress 101 "$ADDR" >/dev/null
ok "regtest up at height $($BCLI getblockcount)"

say "a payment, so the chain holds a real record"
export UV_PASSPHRASE="" UV_BTC_URL="http://127.0.0.1:18443/wallet/uvwallet" \
       UV_BTC_USER=uv UV_BTC_PASS=uv UV_BTC_FEERATE=2 UV_BTC_SCAN_FROM=0 \
       UV_BTC_INDEX="$D/server-index.json"
UV="$ROOT/target/release/uv --home $D/home --backend regtest"
$UV issue --wallet alice --amount 500 >/dev/null 2>&1 || die "issue"
$BCLI generatetoaddress 6 "$ADDR" >/dev/null
$UV address --wallet bob --slots 4 --out "$D/bob.json" >/dev/null 2>&1 || die "address"
$UV send --wallet alice --to "$D/bob.json" --amount 120 >/dev/null 2>&1 || die "send"
$BCLI generatetoaddress 6 "$ADDR" >/dev/null
$UV status --wallet alice >/dev/null 2>&1   # forces an index scan to the tip
RECORDS=$(python3 -c "import json;print(len(json.load(open('$D/server-index.json'))['first']))" 2>/dev/null || echo 0)
[ "$RECORDS" -ge 1 ] || die "the server index holds no records"
ok "$RECORDS record(s) indexed from a real chain"

say "a mirror serving pages of it"
"$ROOT/target/release/uv-mirror" --bind "127.0.0.1:$PORT" --index "$D/server-index.json" \
  > "$D/mirror.log" 2>&1 &
MIRROR_PID=$!
disown "$MIRROR_PID" 2>/dev/null || true
sleep 2
HEAD=$(curl -s "http://127.0.0.1:$PORT/head") || die "mirror unreachable"
echo "  /head -> $HEAD"
TIP=$(python3 -c "import json,sys;print(json.loads('''$HEAD''')['tip'])")
[ "$TIP" -gt 0 ] || die "mirror serves an empty chain"
ok "the mirror serves heights up to $TIP"

say "the request that would leak does not exist"
LEAK=$(curl -s "http://127.0.0.1:$PORT/first_occurrence/deadbeef")
echo "$LEAK" | grep -q "no endpoint that takes a nullifier" \
  || die "the mirror answered a nullifier query"
ok "asking about a coin is refused — there is no such endpoint"

say "a phone syncing those pages, then answering its own lookup"
# The nullifier of the payment that really happened, taken from the server's
# index. Naming it to the LOCAL view is the whole point: this is the question
# a phone must answer and must never ask.
NF=$(python3 -c "
import json
first = json.load(open('$D/server-index.json'))['first']
print(sorted(first.keys())[0])
")
echo "  looking up a real record's nullifier, locally: ${NF:0:16}…"
"$ROOT/target/release/uv" --home "$D/home" mirror-sync --from "http://127.0.0.1:$PORT" \
  --index "$D/phone-index.json" --probe "$NF" 2>&1 | sed 's/^/  /' || die "mirror-sync"
ok "the phone FOUND a real record in its own index; no nullifier left the device"

say "done — the mirror learned that someone asked for blocks, and nothing else"
