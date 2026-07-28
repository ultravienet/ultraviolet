# Two machines, one relay, real signet

`demo/relay.sh` proves the mechanics over loopback and runs in CI. This is the
same thing between two people who share nothing but a network and Bitcoin.

**Read this first: it is a research project, not money.** The circuits have not
had a professional review ([AUDIT-BRIEF.md](../AUDIT-BRIEF.md)). Signet coins are
worthless on purpose. Do not put value on this.

## What actually has to travel

Four channels, and only one of them is Bitcoin's job:

| | Direction | How | When |
|---|---|---|---|
| the anchor | issuer → everyone | `uv anchor export` / `import` | once |
| an address | payee → payer | a file, handed over | once per counterparty |
| the bundle | payer → payee | the relay | per payment |
| the record | payer → Bitcoin | signet | per payment |

The anchor and the address are **public but unauthenticated** — an anchor from
the wrong hands makes a forged lineage look valid, and a substituted address
redirects a payment. Get them from the person, over a channel where you would
recognise them being replaced. That is a real limitation and it is what real
Signal fixes for free, because Signal already authenticates who you are talking
to (spec/99 `[SIGNAL]`).

## Each side needs

- Its **own** signet `bitcoind`. Sharing one works mechanically — the payee only
  makes read calls — but the chain view is trusted for *completeness*, so a payee
  reading the payer's node has made the payer the judge of their own double
  spend ([spec/03](../spec/03-RECORDS.md)). Use your own.
- A funded Core wallet at the RPC endpoint. The payer needs it to publish
  records; the payee does not.
- `cargo build --release -p uv-cli`.

## One of you runs the relay

```bash
uv-relay --bind 0.0.0.0:8787 --dir ./bag
```

It holds opaque blobs and hands them all back on request. It has no accounts, no
rate limit, no expiry and no deletion — anyone who can reach it can drop anything
and fetch everything. That is fine for two people trying this out and is not a
service to leave open on the internet. What it cannot do is read a payment: the
bundle is sealed to the payee's scan key before it ever leaves the payer, and
there is no addressee on it to leak, because recipients find their own mail by
trying to open everything.

Both sides then:

```bash
export UV_RELAY_URL=http://<relay-host>:8787
export UV_BTC_URL=http://127.0.0.1:38332/wallet/uvwallet
export UV_BTC_USER=... UV_BTC_PASS=... UV_BTC_FEERATE=2
export UV_BTC_INDEX="$HOME/.uv/index.json"     # keep it out of the cwd
UV="uv --home $HOME/.uv --backend signet --transport relay"
```

## Alice: issue, and publish the anchor

```bash
$UV issue --wallet alice --amount 1000
$UV anchor export --out anchor.json
# send anchor.json to Bob
```

## Bob: install it, and hand back an address

```bash
$UV anchor import --from anchor.json
$UV address --wallet bob --slots 8 --for alice --out bob.json
# send bob.json to Alice
```

**One batch per counterparty.** Slot reservations are tracked by the *payer*, so
two payers holding one address both start at slot 0 and one of them ends up with
a settled payment that has nowhere to sit (spec/99 `[SLOT-COLLISION]`). `--for`
records who got which batch; `uv status` lists them.

## Alice: pay

```bash
$UV send --wallet alice --to bob.json --amount 300
```

The record goes to signet and the sealed bundle goes to the relay. If the relay
is down you will see `BUNDLE NOT MAILED` — the payment is still settled, and
re-running the same command rebroadcasts the identical record and mails the
bundle. It does not sign anything a second time; it cannot.

## Bob: wait three blocks, then collect

```bash
$UV scan --wallet bob        # fetches from the relay, validates, ingests
$UV balance --wallet bob
$UV status  --wallet bob     # when the answer is not what you expected
```

Signet blocks are ~10 minutes, and the confirmation policy wants three, so
budget half an hour. `uv status` is the thing to read when a balance is not what
you expect: it separates "the record is not deep enough yet" from "my chain view
cannot see far enough back" from "the mail never arrived".

## What this does not prove

The relay is ours. It shows a payment crossing a network between two strangers,
which is the thing the shared directory could never show — and it says nothing
about Signal. Making the carrier real Signal is spec/99 `[SIGNAL]`, and it is a
transport swap, not a redesign: the bundle is already sealed, already opaque, and
already has no addressee.
