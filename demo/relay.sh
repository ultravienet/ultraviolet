#!/usr/bin/env bash
# Two wallets, two homes, one socket: a payment that crosses a network.
#
# Everything in `demo/local2.sh` shares one `--home`, which quietly means the
# payer and payee share the trust anchor, the chain and the mailbox. This runs
# them as two strangers who share only what two machines really do:
#
#   the anchor    exported and imported, once
#   the address   handed over, once
#   the bundle    over the relay, per payment
#   Bitcoin       (here, a copied chain.json standing in for it)
#
# CI can run this because a socket does not need a second machine. What it does
# NOT prove is two *hosts* — for that see demo/two-machines.md, which is the
# same script with the loopback address replaced.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UV="$ROOT/target/release/uv"
RELAY_BIN="$ROOT/target/release/uv-relay"
[ -x "$UV" ] && [ -x "$RELAY_BIN" ] || {
  echo "build first: cargo build --release -p uv-cli"; exit 1; }

D="${1:-$ROOT/uv-relay-demo}"
rm -rf "$D"; mkdir -p "$D/alice" "$D/bob" "$D/bag"
PORT="${UV_RELAY_PORT:-8788}"

say () { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }

"$RELAY_BIN" --bind "127.0.0.1:$PORT" --dir "$D/bag" > "$D/relay.log" 2>&1 &
RELAY_PID=$!
cleanup () { kill "$RELAY_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for the listener rather than sleeping a guessed amount.
for _ in $(seq 1 50); do
  (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3<&-; break; }
  sleep 0.2
done

export UV_PASSPHRASE="" UV_RELAY_URL="http://127.0.0.1:$PORT"
alice () { "$UV" --home "$D/alice" --transport relay "$@"; }
bob   () { "$UV" --home "$D/bob"   --transport relay "$@"; }
# Bitcoin is genuinely shared between two machines; on the mock backend it is a
# file, so copying it is what "both parties see the same chain" means here.
sync_chain () { cp "$D/alice/chain.json" "$D/bob/chain.json"; }

say "the relay is up, and it is deliberately stupid"
head -3 "$D/relay.log"

say "alice issues; bob imports the anchor (channel 1 of 3)"
alice issue --wallet alice --amount 1000 >/dev/null
alice anchor export --out "$D/anchor.json" >/dev/null
bob anchor import --from "$D/anchor.json" | head -1

say "bob hands alice an address (channel 2 of 3)"
bob address --wallet bob --slots 4 --for alice --out "$D/bob.json" | tail -2

say "alice pays 300 — the bundle goes over the socket (channel 3 of 3)"
SEND=$(alice send --wallet alice --to "$D/bob.json" --amount 300)
echo "$SEND" | grep -E "record published|bundle mailed"
case "$SEND" in
  *"via relay"*) ;;
  *) echo "FAIL: the bundle did not go via the relay" >&2; exit 1 ;;
esac
# Nothing was written into bob's inbox by this script. If the relay is not
# doing the work, the scan below finds nothing.
BOB_INBOX=0
for f in "$D"/bob/mailbox/inbox/*.uvb; do [ -e "$f" ] && BOB_INBOX=$((BOB_INBOX+1)); done
[ "$BOB_INBOX" = "0" ] || { echo "FAIL: bob's inbox was not empty before fetching" >&2; exit 1; }

alice mine --blocks 3 >/dev/null
sync_chain

say "bob scans: he fetches from the relay and takes the money"
OUT=$(bob scan --wallet bob); echo "$OUT"
case "$OUT" in
  *"fetched 1 new bundle"*) ;;
  *) echo "FAIL: bob did not fetch anything from the relay" >&2; exit 1 ;;
esac
BAL_ALL=$(bob balance --wallet bob); BAL=${BAL_ALL%%$'\n'*}
if [ "$BAL" = "300" ]; then
  echo "VERIFIED: two homes, no shared mailbox, payment delivered over a socket"
else
  echo "FAIL: bob holds '$BAL', expected 300" >&2; exit 1
fi

say "the relay learns nothing"
python3 - "$D/bag" <<'PY'
import os, sys, zlib
d = sys.argv[1]
names = sorted(os.listdir(d))
assert names, "the relay stored nothing"
blob = open(os.path.join(d, names[0]), "rb").read()
ratio = len(zlib.compress(blob)) / len(blob)
for probe in (b"amount", b"lineage", b"index", b"asset", b"proof"):
    assert probe not in blob, f"PLAINTEXT LEAK: {probe!r} is readable in the relay's copy"
assert ratio > 0.95, f"blob compresses to {ratio:.2f} — that is not ciphertext"
print(f"VERIFIED: {len(blob)} bytes, incompressible ({ratio:.3f}), no plaintext field names")
PY

say "a second scan re-fetches nothing (the cursor is client-side)"
AGAIN=$(bob scan --wallet bob)
case "$AGAIN" in
  *"fetched"*) echo "FAIL: bob re-fetched mail he already has: $AGAIN" >&2; exit 1 ;;
  *) echo "VERIFIED: the cursor advanced, so the bag is not re-downloaded every scan" ;;
esac

say "a payment survives the relay dying: the money is settled either way"
kill "$RELAY_PID" 2>/dev/null || true
wait "$RELAY_PID" 2>/dev/null || true
DOWN=$(alice send --wallet alice --to "$D/bob.json" --amount 100 2>&1 || true)
case "$DOWN" in
  *"record published"*)
    case "$DOWN" in
      *"BUNDLE NOT MAILED"*)
        echo "VERIFIED: the record settled and the CLI said plainly that only delivery failed" ;;
      *) echo "FAIL: the relay was down but the send claimed success: $DOWN" >&2; exit 1 ;;
    esac ;;
  *) echo "FAIL: a dead relay stopped the payment settling: $DOWN" >&2; exit 1 ;;
esac

# ...and when it comes back, re-running mails it, because the record replays.
"$RELAY_BIN" --bind "127.0.0.1:$PORT" --dir "$D/bag" >> "$D/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 50); do
  (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { exec 3<&-; break; }
  sleep 0.2
done
SPENT=$(alice balance --wallet alice | awk '$1=="InFlight"{print $3; exit}')
RETRY=$(alice send --wallet alice --to "$D/bob.json" --amount 100 --from "$SPENT" 2>&1 || true)
case "$RETRY" in
  *REBROADCAST*) echo "VERIFIED: the retry rebroadcast the original payload rather than proving again" ;;
  *) echo "FAIL: the retry did not replay: $RETRY" >&2; exit 1 ;;
esac

say "done — a payment crossed a network and the carrier learned nothing"
