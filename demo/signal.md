# A payment over real Signal

`demo/relay.sh` proves a payment crosses a network. This carries one over
**Signal's own servers, unmodified** — which is the difference between arguing
spec/05's claim and demonstrating it.

**Read this first: it is a research project, not money.** The circuits have not
had a professional review ([AUDIT-BRIEF.md](../AUDIT-BRIEF.md)). Signet coins are
worthless on purpose. Do not put value on this.

## What this does and does not show

**Shows:** Signal carries a payment as an ordinary attachment. No server change,
no protocol change, no cooperation from Signal required — which is the whole
claim in [spec/05](../SPEC.md).

**Does not show:** that Signal would ever ship a payment feature, or that this
is a supported way to use their service. `signal-cli` is a third-party client
Signal does not support. It links the way Signal Desktop does — as a secondary
device on *your own* account — so nothing here registers a new number or touches
anyone else's account. Whether Signal wants any of this is `[WATCH-SIGNAL]`, a
business question this cannot answer.

Also unchanged: the bundle is sealed to the payee's scan key **before** it
becomes an attachment. Signal encrypts it again in transit. A compromise of the
Signal account still does not open a payment — the money never depends on the
carrier.

## One-time setup, each side

You each need a Signal account on a phone, and signal-cli linked to it.

```bash
brew install signal-cli          # or your platform's package
signal-cli link -n "uv"          # prints sgnl://linkdevice?uuid=...
```

Turn that URI into a QR code and scan it from **Settings → Linked devices** in
your Signal app, exactly as you would for Signal Desktop. Nothing is registered;
your existing account gains a device.

Then run the daemon, because signal-cli is a JVM and starting it per command is
painfully slow:

```bash
signal-cli -a "+<your number>" daemon --http 127.0.0.1:8080
```

## Point `uv` at it

```bash
export UV_SIGNAL_URL=http://127.0.0.1:8080
export UV_SIGNAL_TO="+<the other person's number>"
export UV_BTC_URL=http://127.0.0.1:38332/wallet/uvwallet
export UV_BTC_USER=... UV_BTC_PASS=... UV_BTC_FEERATE=2
export UV_BTC_INDEX="$HOME/.uv/index.json"
UV="uv --home $HOME/.uv --backend signet --transport signal"
```

Each side still needs its **own** signet `bitcoind` — the chain view is trusted
for completeness, so reading the payer's node makes the payer the judge of their
own double spend ([spec/03](../SPEC.md)).

## Pay

The three channels are the same as ever; only the carrier changed.

```bash
# Alice
$UV issue  --wallet alice --amount 1000
$UV anchor export --out anchor.json          # send over Signal, by hand

# Bob
$UV anchor import --from anchor.json
$UV address --wallet bob --slots 8 --for alice --out bob.json   # send back

# Alice
$UV send   --wallet alice --to bob.json --amount 300

# Bob, after three signet blocks (~30 min)
$UV scan    --wallet bob
$UV balance --wallet bob
$UV status  --wallet bob      # when the answer is not what you expected
```

**The anchor and address still travel by hand — and now Signal is what
authenticates them.** Neither carries a signature; an anchor from the wrong hands
makes a forged lineage look valid, and a substituted address redirects a payment.
Sending them through the same Signal conversation you already trust is what
closes that, with no new cryptography. Making it automatic is the unbuilt
"in-band address exchange" in spec/99 `[SIGNAL]`.

## Trying it alone

Note-to-Self proves the **sending** half and only that half:

```bash
export UV_SIGNAL_TO="+<your own number>"
```

The bundle really goes to Signal and really arrives — it shows up as an
attachment in Note to Self on your phone. But **a device does not receive its
own sent message.** Signal delivers a sent-transcript to your *other* devices,
so the signal-cli instance that sent it will never see it come back, and a scan
on that machine finds nothing however long you wait. That is Signal working
correctly, not a fault.

Measured 2026-07-28: send succeeded, `attachments/` stayed empty, and the
receiving scan correctly reported no mail. Later the same day the two-account
round trip ran for real — the ledger below is that run.

The honest end-to-end test is **two real accounts**, and it has now been run —
see the ledger below. With both accounts linked into one signal-cli data
directory, no `--config` juggling is needed; each daemon serves one account by
number and both share the same `attachments/` directory, which is fine because
the transport identifies bundles by content, not by which account fetched them:

```bash
signal-cli --account "+<payer>" daemon --http 127.0.0.1:8080
signal-cli --account "+<payee>" daemon --http 127.0.0.1:8081
# payer:  UV_SIGNAL_URL=http://127.0.0.1:8080  UV_SIGNAL_TO="+<payee>"
# payee:  UV_SIGNAL_URL=http://127.0.0.1:8081
```

## When it does not work

- **`signal-cli daemon unreachable`** — the daemon is not running, or is on a
  different port. It takes a few seconds to start.
- **`signal-cli refused 'send'`** — usually an unregistered recipient. The number
  must be someone who actually uses Signal, in `+<country><number>` form.
- **Nothing arrives** — a linked device only receives messages sent *after* it
  was linked. Check the daemon's own output; it logs what it fetched.
- **Nothing arrives, and the daemon logs nothing either** — this happened on the
  first real run. A daemon started with `--no-receive-stdout` sat connected for
  half an hour while the phone showed the message delivered; restarting it
  *without* that flag flushed the whole queue instantly, envelope log lines and
  all. Until the cause is pinned down, run the receiving daemon without
  `--no-receive-stdout` and confirm you see `Envelope from:` lines — a daemon
  that logs envelopes is receiving, and one that logs nothing is not a daemon
  that has nothing to receive.
- **The scan says `InsufficientDepth`** — the payment arrived and is simply not
  three blocks deep yet. Signet blocks are ~10 minutes. This is correct
  behaviour, not a failure.

## Recording a run

This cannot run in CI — CI has no Signal account — so a successful run is worth
writing down the way `formal/verify.sh` results are:

The second column is a **content hash of the transport sources**
(`./scripts/subject-hash.sh cli/src/transport.rs signal/src/lib.rs`), not a git
commit — this repository keeps one always-amended commit, so a commit hash here
could never resolve. If the subject hash matches, the row still describes the
code in front of you.

| Date | Subject (transport) | signal-cli | What moved | Ran by |
|---|---|---|---|---|
| 2026-07-28 | `a94f919ccd127402` | 0.14.6 | 300 units, +14045076277 → +14045076749, on **public signet**: 76-byte issuance record and 64-byte spend record both confirmed (txids `a1ce8666…`, `4f825b57…`, 4 deep at acceptance); 214,460-byte sealed bundle carried by Signal's own servers, delivered in <1 s, verified on the phone's Signal app and fetched by the payee's linked signal-cli; first scan accepted 300 (1 hop); `uv supply --asset` read 1000 attested off signet from the payee's own view | agent + posix4e |

An entry here is the evidence for the spec/05 claim. Without one, the claim is
back to being argued.
