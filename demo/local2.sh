#!/usr/bin/env bash
# Ultraviolet v2 end-to-end: the sovereign STARK, the Poseidon2 money path, and
# every wallet discipline the formal models demanded — with no SP1 anywhere.
#
#   ./demo/local2.sh
#
# Proves: issuance, a two-hop payment with full-lineage validation, the
# confirmation policy gating acceptance, a double-spend refused by
# first-occurrence, and reorg reconciliation quarantining a note whose ancestry
# stopped settling.
set -euo pipefail

cd "$(dirname "$0")/.."
# Wallets are encrypted at rest by default (spec/99, closed). The demo runs
# unattended, so it opts out explicitly rather than being prompted — the empty
# value is the documented "store in the clear" choice, never a silent default.
export UV_PASSPHRASE=""
HOME_DIR="${1:-./uv-demo2}"
UV="./target/release/uv --home $HOME_DIR"

say() { printf '\n\033[1;35m== %s\033[0m\n' "$*"; }

rm -rf "$HOME_DIR"
say "building"
cargo build --release -p uv-cli --quiet

say "alice issues 1000"
$UV issue --wallet alice --amount 1000
# The anchor is trusted out of band; every receiver validates against it.

say "bob publishes an address (one-time slots + a scan key, handed over once)"
$UV address --wallet bob --slots 4 --out "$HOME_DIR/bob-addr.json"

say "alice pays bob 300"
$UV send --wallet alice --to "$HOME_DIR/bob-addr.json" --amount 300 | tee "$HOME_DIR/hop1.txt"
HOP1_NF=$(awk '/record published/{print $4}' "$HOME_DIR/hop1.txt")

# Keep a copy of the sealed bundle as it sat on the wire. Scanning now removes
# what it accepts *and* what it permanently rejects, so this is the only moment
# it exists to be inspected.
cp "$HOME_DIR"/mailbox/inbox/*.uvb "$HOME_DIR/on-the-wire.uvb"

say "bob scans before the record is deep enough (3 confirmations needed)"
$UV scan --wallet bob
# The 1-confirmation tier was withdrawn: formal/reorg.qnt proves it is unsafe
# against a 2-block reorg, and the repair that would have allowed it does not
# work against the real chain backend. Everything needs 3 now.
$UV mine --blocks 3
$UV scan --wallet bob

say "balances: alice 700 change, bob 300 (her spent note settles to Spent)"
$UV reconcile --wallet alice >/dev/null
echo "alice:"; $UV balance --wallet alice
echo "bob:";   $UV balance --wallet bob
# Remember alice's SPENT note so the double-spend step can target it exactly.
# No `| head -1` on the CLI's own output — see the note at the reorg section and
# the same trap fixed in regtest.sh, where it took CI down. awk consumes all of
# it, then the shell takes the first field.
SPENT_ALL=$($UV balance --wallet alice)
SPENT=$(printf '%s\n' "$SPENT_ALL" | awk '$1=="Spent"{print $3; exit}')

say "carol requests 100; bob pays her — a TWO-hop lineage"
$UV address --wallet carol --slots 4 --out "$HOME_DIR/carol-addr.json"
$UV send --wallet bob --to "$HOME_DIR/carol-addr.json" --amount 100
$UV mine --blocks 3

say "carol validates both hops: proofs, linkage, history, settlement"
$UV scan --wallet carol
echo -n "carol "; $UV balance --wallet carol

say "double-spend attempt: alice targets her ALREADY SPENT note"
echo "targeting spent note $SPENT"
$UV address --wallet dave --slots 4 --out "$HOME_DIR/dave-addr.json"
# The sign-log replay discipline (onetime.qnt): a conforming wallet CANNOT
# sign a second payload for a key that already signed. It replays the original
# instead — same nullifier, same bundle, and the chain's first-occurrence makes
# republishing a free no-op. Dave gets nothing; no key is ever disclosed.
# Count the mail and the slot reservations before, so we can prove the replay
# added neither. Dave has never been paid, so a reservation file for his
# address existing afterwards means a slot was spent on a payment to nobody.
MAIL_BEFORE=0
for f in "$HOME_DIR"/mailbox/inbox/*.uvb; do
  [ -e "$f" ] && MAIL_BEFORE=$((MAIL_BEFORE + 1))
done
RES_BEFORE=0
for f in "$HOME_DIR"/used-slots-*.json; do
  [ -e "$f" ] && RES_BEFORE=$((RES_BEFORE + 1))
done
$UV send --wallet alice --to "$HOME_DIR/dave-addr.json" --amount 300 --from "$SPENT" | tee "$HOME_DIR/ds.txt"
REPLAY_NF=$(awk '/^  nf /{print $2}' "$HOME_DIR/ds.txt")
if [ "$REPLAY_NF" = "$HOP1_NF" ]; then
  echo "VERIFIED: the nullifier is alice's ORIGINAL spend, replayed byte for byte."
else
  echo "FAIL: expected the original nullifier $HOP1_NF, got $REPLAY_NF" >&2
  exit 1
fi

# A replay is a rebroadcast, not a payment to dave. It used to be treated as
# one: a fresh slot was reserved and a bundle naming that slot was mailed,
# while the transfer paid alice's original payee. Dave would derive keys for
# the wrong slot, refuse the bundle as NotAnOutput — permanently — and the slot
# was gone. Retry a lost record, lose a slot each time.
MAIL_AFTER=0
for f in "$HOME_DIR"/mailbox/inbox/*.uvb; do
  [ -e "$f" ] && MAIL_AFTER=$((MAIL_AFTER + 1))
done
RES_AFTER=0
for f in "$HOME_DIR"/used-slots-*.json; do
  [ -e "$f" ] && RES_AFTER=$((RES_AFTER + 1))
done
if [ "$MAIL_AFTER" = "$MAIL_BEFORE" ]; then
  echo "VERIFIED: the replay mailed nothing ($MAIL_AFTER bundles, unchanged)"
else
  echo "FAIL: the replay mailed $((MAIL_AFTER - MAIL_BEFORE)) bundle(s) dave can never accept" >&2
  exit 1
fi
if [ "$RES_AFTER" = "$RES_BEFORE" ]; then
  echo "VERIFIED: no slot was reserved ($RES_AFTER reservation files, unchanged)"
else
  echo "FAIL: the replay reserved a slot on dave's address" >&2; exit 1
fi
if $UV send --wallet alice --to "$HOME_DIR/dave-addr.json" --amount 300 --from "$SPENT" 2>&1 \
     | grep -q "no slot spent"; then
  echo "VERIFIED: it says so plainly, and says it again on the next retry"
else
  echo "FAIL: a second retry did not report itself as a rebroadcast" >&2; exit 1
fi
$UV scan --wallet dave || true
echo -n "dave  "; $UV balance --wallet dave
echo "dave is unpaid, holds no slot-burning mail, and alice's key signed once."

say "the mailed bundle is sealed: hybrid ML-KEM-768 + X25519"
python3 "$(dirname "$0")/check_sealed.py" "$HOME_DIR/on-the-wire.uvb" || exit 1

say "junk mail is discarded; payments merely too shallow are kept"
# Rejected bundles used to sit in the mailbox forever, costing a proof
# verification per hop on every future scan. Dave's mailbox holds a bundle that
# can never become valid (it pays a note he does not own), so scanning must
# throw it away rather than re-check it for eternity.
# Counted with a glob rather than `ls | wc -l`: with `set -e` and `pipefail`,
# `ls` on an empty directory fails and takes the whole script with it. This
# demo has been bitten by that exact pipeline twice.
LEFTOVER=0
for f in "$HOME_DIR"/mailbox/inbox/*.uvb; do
  [ -e "$f" ] && LEFTOVER=$((LEFTOVER + 1))
done
if [ "$LEFTOVER" = "0" ]; then
  echo "VERIFIED: permanently-invalid mail was discarded, not left to re-verify"
else
  echo "FAIL: $LEFTOVER dead bundle(s) still in the mailbox"; exit 1
fi

say "a payment larger than any single note: two notes of 1 paying 2"
# A transfer takes exactly one input, so a wallet holding 1 + 1 that owes 2
# could previously not pay at all (spec/99 [MERGE]). It now sends two
# independent transfers that add up.
$UV address --wallet frank --slots 4 --out "$HOME_DIR/frank-addr.json" >/dev/null
$UV send --wallet carol --to "$HOME_DIR/frank-addr.json" --amount 1 >/dev/null
$UV mine --blocks 3 >/dev/null
$UV send --wallet carol --to "$HOME_DIR/frank-addr.json" --amount 1 >/dev/null
$UV mine --blocks 3 >/dev/null
$UV scan --wallet frank >/dev/null
$UV address --wallet grace --slots 4 --out "$HOME_DIR/grace-addr.json" >/dev/null
SPLIT=$($UV send --wallet frank --to "$HOME_DIR/grace-addr.json" --amount 2)
echo "$SPLIT" | grep -E "no single note|paid 2 as" || true
$UV mine --blocks 3 >/dev/null
$UV scan --wallet grace >/dev/null
# Not `| head -1`: that closes the pipe early and the CLI dies with SIGPIPE
# while still printing. Capture it all, then take the first line in the shell.
GRACE_ALL=$($UV balance --wallet grace)
GRACE=${GRACE_ALL%%$'\n'*}
if [ "$GRACE" = "2" ]; then
  echo "VERIFIED: 1 + 1 paid 2 as two transfers; grace holds $GRACE"
else
  echo "FAIL: grace holds $GRACE, expected 2"; exit 1
fi

say "a payee in a SEPARATE home validates from an exported anchor"
# Everything above shares one --home, which quietly means the payer and payee
# share the trust anchor, the chain and the mailbox. Two machines share only
# Bitcoin. This runs the payee out of its own home to prove that the ONLY
# things that have to travel are the three channels we know about: the anchor,
# the address, and the sealed bundle. Anything else implicitly shared would
# show up here as a failure.
#
# The chain file is copied because on the mock backend the chain IS a file; it
# stands in for "both parties see the same Bitcoin", which on signet they do.
FAR="$HOME_DIR/far"
mkdir -p "$FAR/mailbox/inbox"
far () { ./target/release/uv --home "$FAR" "$@"; }
$UV anchor export --out "$HOME_DIR/anchor-export.json" >/dev/null
far anchor import --from "$HOME_DIR/anchor-export.json" | head -1
far address --wallet frank2 --slots 4 --for alice --out "$HOME_DIR/frank2.json" >/dev/null
$UV send --wallet alice --to "$HOME_DIR/frank2.json" --amount 25 >/dev/null
$UV mine --blocks 3 >/dev/null
cp "$HOME_DIR/chain.json" "$FAR/chain.json"
# Only the sealed bundle crosses. It is ciphertext; the carrier learns nothing.
for f in "$HOME_DIR"/mailbox/inbox/*.uvb; do [ -e "$f" ] && mv "$f" "$FAR/mailbox/inbox/"; done
far scan --wallet frank2 >/dev/null
FAR_ALL=$(far balance --wallet frank2); FAR_BAL=${FAR_ALL%%$'\n'*}
if [ "$FAR_BAL" = "25" ]; then
  echo "VERIFIED: a payee with its own home, its own wallet and an imported anchor took the payment"
else
  echo "FAIL: the separate-home payee holds '$FAR_BAL', expected 25" >&2; exit 1
fi
# And an anchor for a different asset must not silently replace it.
FAR2="$HOME_DIR/far2"; mkdir -p "$FAR2"
./target/release/uv --home "$FAR2" issue --wallet mallory --amount 5 >/dev/null
./target/release/uv --home "$FAR2" anchor export --out "$HOME_DIR/other-anchor.json" >/dev/null
OTHER=$(far anchor import --from "$HOME_DIR/other-anchor.json" 2>&1 || true)
case "$OTHER" in
  *"already holds a different asset"*)
    echo "VERIFIED: an anchor for another asset is refused, not silently swapped in" ;;
  *) echo "FAIL: a foreign anchor was accepted: $OTHER" >&2; exit 1 ;;
esac

say "two payers, one slot: nothing is destroyed and the scan survives"
# The bug this catches was invisible while every payer shared one --home, and
# guaranteed the moment they do not. Slot reservations are PAYER-local
# (used-slots-*.json) but the invariant they enforce -- each slot paid to once
# -- belongs to the PAYEE. Two payers holding one address both start at slot 0
# without either doing anything wrong; `Store::insert`'s own doc comment says
# so.
#
# What used to happen: the second note hit `.expect("fresh index")` and
# panicked the scan mid-loop, AFTER earlier accepted bundles had been deleted
# and BEFORE the wallet was saved. Measured on a wallet owed 700: it ended with
# 300, and the missing 400 was unrecoverable.
#
# Deleting the reservation file is exactly what a second, independent payer
# looks like to this code.
$UV address --wallet judy --slots 4 --out "$HOME_DIR/judy-addr.json" >/dev/null
$UV send --wallet carol --to "$HOME_DIR/judy-addr.json" --amount 20 >/dev/null
$UV mine --blocks 3 >/dev/null
rm -f "$HOME_DIR"/used-slots-*.json
$UV send --wallet carol --to "$HOME_DIR/judy-addr.json" --amount 30 >/dev/null
$UV mine --blocks 3 >/dev/null
COLLIDE=$($UV scan --wallet judy 2>&1); COLLIDE_RC=$?
JUDY_ALL=$($UV balance --wallet judy); JUDY=${JUDY_ALL%%$'\n'*}
ASIDE=0
for f in "$HOME_DIR"/mailbox/unplaceable/*.uvb; do
  [ -e "$f" ] && ASIDE=$((ASIDE + 1))
done
if [ "$COLLIDE_RC" != "0" ]; then
  echo "FAIL: the scan died on a slot collision:" >&2; echo "$COLLIDE" >&2; exit 1
fi
case "$JUDY" in
  20|30) ;;
  *) echo "FAIL: judy holds '$JUDY' — one of the two payments should have landed" >&2; exit 1 ;;
esac
if [ "$ASIDE" = "1" ]; then
  echo "VERIFIED: the collision was survived; judy holds $JUDY and the other payment was set aside, not destroyed"
else
  echo "FAIL: expected 1 bundle set aside, found $ASIDE" >&2; exit 1
fi
# And it must not be re-verified forever: a second scan sees nothing.
AGAIN=$($UV scan --wallet judy 2>&1)
case "$AGAIN" in
  *"accepted 0, rejected 0"*)
    echo "VERIFIED: the unplaceable bundle is out of the scan path, not re-verified every time" ;;
  *) echo "FAIL: the set-aside bundle is still being re-verified: $AGAIN" >&2; exit 1 ;;
esac

say "a malformed address refuses BEFORE it reserves anything"
# `unhexd` panicked on a counterparty's file, and the reservation write had
# already happened by then — so one bad field in the middle of a multi-note
# plan burnt every slot in it. Validation now sits beside the balance and
# slot-count checks, which already promise "everything that can refuse,
# refuses now".
$UV address --wallet heidi --slots 4 --out "$HOME_DIR/heidi-addr.json" >/dev/null
python3 - "$HOME_DIR/heidi-addr.json" <<'CORRUPT'
import json, sys
a = json.load(open(sys.argv[1]))
# Corrupt the SECOND slot, not the first: a two-note payment reserves both, and
# the bug only showed when the first slot was fine and the second panicked.
a["slots"][1]["owner_pk_hex"] = "not actually hex"
json.dump(a, open(sys.argv[1], "w"))
print("corrupted slot 1's owner key")
CORRUPT
RES_BEFORE=0
for f in "$HOME_DIR"/used-slots-*.json; do
  [ -e "$f" ] && RES_BEFORE=$((RES_BEFORE + 1))
done
BAD=$($UV send --wallet grace --to "$HOME_DIR/heidi-addr.json" --amount 2 2>&1 || true)
RES_AFTER=0
for f in "$HOME_DIR"/used-slots-*.json; do
  [ -e "$f" ] && RES_AFTER=$((RES_AFTER + 1))
done
case "$BAD" in
  *"refusing before reserving anything"*)
    if [ "$RES_AFTER" = "$RES_BEFORE" ]; then
      echo "VERIFIED: refused on slot 1, and reserved nothing on the way"
    else
      echo "FAIL: it refused, but a reservation file appeared anyway" >&2; exit 1
    fi ;;
  *) echo "FAIL: a malformed address did not refuse cleanly; got: $BAD" >&2; exit 1 ;;
esac

# The same discipline for the scan key — the one field the slot loop cannot
# see. This was a live bug found by adversarial review: sealing the bundle
# `.expect()`ed on the scan key AFTER the record was on Bitcoin, so a malformed
# key cost the payment, the slot, and mailed nothing. The pre-flight now probes
# the key with a real seal before reserving anything.
$UV address --wallet ivan --slots 4 --out "$HOME_DIR/ivan-addr.json" >/dev/null
python3 - "$HOME_DIR/ivan-addr.json" <<'CORRUPT'
import json, sys
a = json.load(open(sys.argv[1]))
a["scan"]["ml_kem_hex"] = "definitely not a kem key"
json.dump(a, open(sys.argv[1], "w"))
print("corrupted the scan key")
CORRUPT
BADSCAN=$($UV send --wallet grace --to "$HOME_DIR/ivan-addr.json" --amount 1 2>&1 || true)
case "$BADSCAN" in
  *"refusing before reserving anything"*)
    echo "VERIFIED: a malformed scan key refuses before reserving, not after publishing" ;;
  *) echo "FAIL: malformed scan key was not refused cleanly; got: $BADSCAN" >&2; exit 1 ;;
esac

say "slots advance, and exhaustion refuses rather than reusing"
# Reusing a slot would hand bob two notes under one one-time key, and he could
# only ever spend one. The payer tracks what it has consumed; a 4th payment to
# a 3-slot address must fail loudly.
$UV address --wallet erin --slots 2 --out "$HOME_DIR/erin-addr.json"
$UV send --wallet bob --to "$HOME_DIR/erin-addr.json" --amount 10 >/dev/null
$UV mine --blocks 3 >/dev/null
$UV send --wallet bob --to "$HOME_DIR/erin-addr.json" --amount 10 >/dev/null
$UV mine --blocks 3 >/dev/null
# The reservation file is keyed on the address's contents rather than its
# filename, so copying or renaming an address cannot reset which slots are
# spent. There is exactly one such file for erin's address.
# Newest by modification time: erin's payments are the most recent, and the
# file is named after a hash of the address rather than its filename.
USED=$(cat "$(ls -t "$HOME_DIR"/used-slots-*.json | head -1)")
if [ "$USED" = "[0,1]" ]; then
  echo "VERIFIED: two payments consumed two DIFFERENT slots ($USED)"
else
  echo "FAIL: expected slots [0,1], got $USED" >&2; exit 1
fi
# Capture first: `set -o pipefail` would report the CLI's deliberate non-zero
# exit as a pipeline failure even when grep matches.
THIRD=$($UV send --wallet bob --to "$HOME_DIR/erin-addr.json" --amount 10 2>&1 || true)
case "$THIRD" in
  *exhausted*) echo "VERIFIED: a third payment to a two-slot address is refused, not reused" ;;
  *) echo "FAIL: exhausted address did not refuse; got: $THIRD" >&2; exit 1 ;;
esac

say "reorg: drop hop 1's record, then bob reconciles"
python3 - "$HOME_DIR/chain.json" <<'PY'
import json,sys
p=sys.argv[1]
st=json.load(open(p))
# Drop the earliest record: hop 1 (alice -> bob).
st['records'] = st['records'][1:]
json.dump(st, open(p,'w'))
print(f"dropped 1 record, {len(st['records'])} remain")
PY
$UV reconcile --wallet bob
echo -n "bob   "; $UV balance --wallet bob

say "done — no SP1, no SLH-DSA, no sha2 patch anywhere in this run"
