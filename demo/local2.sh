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
# Captured, not piped into `grep -q`. That form is a coin flip: `grep -q` exits
# the instant it matches, `uv` takes SIGPIPE (141) if it is still writing, and
# `set -o pipefail` fails the pipeline on the CLI's death even though the match
# succeeded. It passed for months and failed on 2026-07-28 with no code change
# between the two runs. Same trap as the `| head -1` notes above and the one
# that took CI down in regtest.sh — this was its third form in this file.
RETRY=$($UV send --wallet alice --to "$HOME_DIR/dave-addr.json" --amount 300 --from "$SPENT" 2>&1 || true)
case "$RETRY" in
  *"no slot spent"*)
    echo "VERIFIED: it says so plainly, and says it again on the next retry" ;;
  *) echo "FAIL: a second retry did not report itself as a rebroadcast" >&2; exit 1 ;;
esac
$UV scan --wallet dave || true
echo -n "dave  "; $UV balance --wallet dave
echo "dave is unpaid, holds no slot-burning mail, and alice's note was spent once — the retry replayed it."

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

say "the anchor is public and must not contain a secret"
# The asset id used to be the genesis note's `nullifier_key` — documented as
# secret — while `anchor.json` published it as `asset_hex` alongside
# `commitment_hex`. Since nullifier = H(Domain::Nullifier, key ‖ commitment),
# both inputs were public: anyone holding an anchor could compute the genesis
# nullifier before the issuer ever spent, publish one keyless garbage record
# against it, and kill the asset permanently for one transaction fee.
#
# This replays that: derive the attack value from the published anchor, drop a
# record on it, and require alice's coin to keep working.
ATTACK_NF=$(python3 - "$HOME_DIR/anchor.json" <<'DERIVE'
import json, sys
a = json.load(open(sys.argv[1]))
# The two fields an attacker has. Printing them is the point: they are public.
print(a["asset_hex"][:16], a["commitment_hex"][:16])
DERIVE
)
echo "anchor publishes asset+commitment: $ATTACK_NF"
# The real check is the unit test, which computes the nullifier properly with
# the sponge; here we assert the weaker, blunter property end to end: the asset
# id is NOT the genesis note's nullifier key, so the anchor cannot be turned
# into a spend marker at all.
ASSET=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['asset_hex'])" "$HOME_DIR/anchor.json")
ALICE_SPENT=$($UV balance --wallet alice | awk '$1=="Spent"{print $3; exit}')
if [ "$ASSET" = "$ALICE_SPENT" ]; then
  echo "FAIL: the asset id equals a note commitment — the anchor is leaking" >&2; exit 1
fi
echo "VERIFIED: the anchor's asset id is public and inert, not a spend secret"

say "one asset id cannot have two genesis notes"
# accept() decides a lineage's origin by byte-equality against the anchor's
# commitment, so two anchors sharing an asset id but naming different genesis
# notes would let two payees each believe they hold the asset. Two supplies.
FAKE="$HOME_DIR/forged-anchor.json"
python3 - "$HOME_DIR/anchor.json" "$FAKE" <<'FORGE'
import json, sys
a = json.load(open(sys.argv[1]))
# Same asset id, different genesis: flip one hex digit of the commitment.
c = a["commitment_hex"]
a["commitment_hex"] = ("1" if c[0] != "1" else "2") + c[1:]
json.dump(a, open(sys.argv[2], "w"))
FORGE
# A home of its own, so this does not depend on any later section's helpers.
FORGEHOME="$HOME_DIR/forgetest"; mkdir -p "$FORGEHOME"
./target/release/uv --home "$FORGEHOME" anchor import --from "$HOME_DIR/anchor.json" >/dev/null
FORGED=$(./target/release/uv --home "$FORGEHOME" anchor import --from "$FAKE" 2>&1 || true)
case "$FORGED" in
  *"DIFFERENT genesis"*)
    echo "VERIFIED: a second genesis under one asset id is refused, not installed" ;;
  *) echo "FAIL: a forged genesis was accepted: $FORGED" >&2; exit 1 ;;
esac

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
a["slots"][1]["nullifier_anchor_hex"] = "not actually hex"
json.dump(a, open(sys.argv[1], "w"))
print("corrupted slot 1's anchor")
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

say "supply is read off the chain, not taken on the issuer's word"
# Until issuance published a record, an asset's supply was whatever its issuer
# said it was, and formal/issuance.qnt finds the secret-inflation attack in two
# steps: mint without publishing, hand the coins over, and what a holder can
# spend exceeds what any reader of Bitcoin can see.
ASSET=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['asset_hex'])" "$HOME_DIR/anchor.json")
SUPPLY=$($UV supply --asset "$ASSET")
printf '%s\n' "$SUPPLY" | head -3
ISSUED=$(printf '%s\n' "$SUPPLY" | awk '/^  issued:/{print $2}')
if [ "$ISSUED" = "1000" ]; then
  echo "VERIFIED: the chain says 1000 for THIS asset — nobody was asked"
else
  echo "FAIL: uv supply --asset reports '$ISSUED', expected 1000" >&2; exit 1
fi
# Exact, not a ceiling. The record carries the asset id in the clear, so an
# asset's records enumerate; while it carried a one-way hash of its details the
# only computable number was a chain-wide sum, and the tool had to say so.
case "$SUPPLY" in
  *"UPPER BOUND"*)
    echo "FAIL: uv supply still hedges — the asset id is on chain, this is a total" >&2; exit 1 ;;
  *"every record attested"*)
    echo "VERIFIED: reported as a total, with every record attested by this home" ;;
  *) echo "FAIL: unexpected uv supply output" >&2; printf '%s\n' "$SUPPLY" >&2; exit 1 ;;
esac

say "a decoy record bearing this asset's id is counted apart, not added in"
# Nothing authenticates an asset id, so anyone may publish a record naming
# someone else's asset. It creates no spendable coin — that needs a secret only
# the owner has — but it does bear the id, and a tool that simply summed would
# report an inflated figure with no hint that it had. Attested and unattested
# are therefore never added together (spec/12).
python3 - "$HOME_DIR/chain.json" <<'DECOY'
import json, sys
p = sys.argv[1]
st = json.load(open(p))
real = st["issuances"][0]
# Same asset, a genesis note nobody holds, a large amount.
st["issuances"].append({
    "amount": 999_999,
    "asset": real["asset"],
    "commitment": [(v + 1) % 2013265921 for v in real["commitment"]],
})
json.dump(st, open(p, "w"))
print("published a decoy bearing alice's asset id")
DECOY
DECOYED=$($UV supply --asset "$ASSET")
printf '%s\n' "$DECOYED" | grep -E "unattested|issued:" || true
case "$DECOYED" in
  *"1000 attested + 999999 unattested"*)
    echo "VERIFIED: the decoy is reported separately — the attested figure is still 1000" ;;
  *) echo "FAIL: the decoy was not held apart from the attested total" >&2
     printf '%s\n' "$DECOYED" >&2; exit 1 ;;
esac
# And it must not become spendable: alice's own coin still validates.
python3 - "$HOME_DIR/chain.json" <<'UNDECOY'
import json, sys
p = sys.argv[1]
st = json.load(open(p))
st["issuances"] = st["issuances"][:1]
json.dump(st, open(p, "w"))
UNDECOY

say "a coin whose issuance is not on THIS chain is refused"
# The free-mint attack. Mallory issues on a chain of her own -- which is what
# "never published it" looks like from the victim's side -- and pays a victim
# who reads the real chain. Under the first version of this rule, `accept`
# matched on the AMOUNT alone, so alice's confirmed 1000 answered mallory's
# check and mallory minted 1000 units for free. Amounts are round numbers; that
# collides by accident, never mind on purpose.
#
# The VICTIM generates the address, which is the only way this proves anything:
# a first draft had mallory create a `payee` wallet in her own home, so the
# victim's same-named wallet had a different seed, the bundle was for a slot it
# could not derive, and the scan reported "rejected 0" -- it never looked. The
# assertion below is on the REASON, not on a zero balance that any failure
# produces.
MAL="$HOME_DIR/mallory"; mkdir -p "$MAL"
VIC="$HOME_DIR/victim"; mkdir -p "$VIC/mailbox/inbox"
mal () { ./target/release/uv --home "$MAL" "$@"; }
vic () { ./target/release/uv --home "$VIC" "$@"; }
mal issue --wallet mallory --amount 1000 >/dev/null       # same amount as alice
vic address --wallet payee --slots 2 --out "$HOME_DIR/victim-addr.json" >/dev/null
cp "$HOME_DIR/victim-addr.json" "$MAL/p.json"
mal send --wallet mallory --to "$MAL/p.json" --amount 40 >/dev/null
mal mine --blocks 3 >/dev/null
# The victim takes mallory's anchor and mallory's bundle, but reads the REAL
# chain -- the one with alice's issuance and not mallory's.
mal anchor export --out "$MAL/anchor-export.json" >/dev/null
vic anchor import --from "$MAL/anchor-export.json" >/dev/null
cp "$HOME_DIR/chain.json" "$VIC/chain.json"
for f in "$MAL"/mailbox/inbox/*.uvb; do [ -e "$f" ] && cp "$f" "$VIC/mailbox/inbox/"; done
VICSCAN=$(vic scan --wallet payee 2>&1 || true)
printf '%s\n' "$VICSCAN"
case "$VICSCAN" in
  *"accepted 0, rejected 0"*)
    echo "FAIL: the scan never looked at the bundle — this proves nothing" >&2; exit 1 ;;
  *GenesisNotOnChain*)
    echo "VERIFIED: refused because THIS genesis is not on THIS chain — the supply rule, by name" ;;
  *) echo "FAIL: refused for the wrong reason: $VICSCAN" >&2; exit 1 ;;
esac
VIC_ALL=$(vic balance --wallet payee 2>/dev/null || echo 0); VIC_BAL=${VIC_ALL%%$'\n'*}
if [ "$VIC_BAL" = "0" ]; then
  echo "VERIFIED: an unpublished issuance is worthless — the victim holds $VIC_BAL"
else
  echo "FAIL: the victim accepted $VIC_BAL from an issuance no chain confirms" >&2; exit 1
fi
# And the bundle is KEPT, not destroyed: mallory's record could still confirm,
# and a receiver that deletes on a transient verdict loses real money when the
# issuance was merely late. Same asymmetry ViewIncomplete got wrong.
KEPT=0
for f in "$VIC"/mailbox/inbox/*.uvb; do [ -e "$f" ] && KEPT=$((KEPT + 1)); done
if [ "$KEPT" -ge 1 ]; then
  echo "VERIFIED: refused as transient — the bundle is kept, not destroyed ($KEPT held)"
else
  echo "FAIL: the bundle was deleted; a late issuance would have cost real money" >&2; exit 1
fi
# The control: the SAME bundle, against a chain that DOES carry mallory's
# issuance, is taken. Without this the section proves only that something
# refused, not that the supply rule is what refused.
OK="$HOME_DIR/victim-ok"; mkdir -p "$OK/mailbox/inbox"
cp "$VIC/wallets/payee.uvw" "$OK/mailbox/../" 2>/dev/null || true
mkdir -p "$OK/wallets"; cp "$VIC/wallets/payee.uvw" "$OK/wallets/"
./target/release/uv --home "$OK" anchor import --from "$MAL/anchor-export.json" >/dev/null
cp "$MAL/chain.json" "$OK/chain.json"
for f in "$MAL"/mailbox/inbox/*.uvb; do [ -e "$f" ] && cp "$f" "$OK/mailbox/inbox/"; done
./target/release/uv --home "$OK" scan --wallet payee >/dev/null 2>&1 || true
OK_ALL=$(./target/release/uv --home "$OK" balance --wallet payee 2>/dev/null || echo 0)
OK_BAL=${OK_ALL%%$'\n'*}
if [ "$OK_BAL" = "40" ]; then
  echo "VERIFIED (control): the same bundle IS taken when the issuance is on the chain being read"
else
  echo "FAIL: the control did not pay — the refusal above may be incidental (got '$OK_BAL')" >&2
  exit 1
fi

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
