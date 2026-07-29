# Stage D — a real record on public signet

Stage C proves the Bitcoin path against a local regtest node. Stage D runs the
**same `BitcoinChain` code** against **public signet**, so a transfer's 64-byte
record becomes a real transaction anyone can look up on a block explorer. The
only differences from regtest: the node doesn't mine its own blocks (you wait
for signet miners), and the wallet is funded from a faucet instead of
`generatetoaddress`.

## 1. Run a signet node

```bash
BTCDIR=$(mktemp -d)/signet
bitcoind -signet -datadir="$BTCDIR" -rpcuser=uv -rpcpassword=uv \
  -rpcport=38332 -fallbackfee=0.0002 -txindex=1 -daemon
# wait for headers/blocks to sync (signet is light — minutes, not hours)
bitcoin-cli -signet -datadir="$BTCDIR" -rpcuser=uv -rpcpassword=uv -rpcport=38332 getblockchaininfo
```

## 2. Create + fund a wallet from the faucet

```bash
CLI="bitcoin-cli -signet -datadir=$BTCDIR -rpcuser=uv -rpcpassword=uv -rpcport=38332"
$CLI createwallet uvwallet
$CLI -rpcwallet=uvwallet getnewaddress
# → paste that address into a signet faucet, e.g. https://signetfaucet.com
# wait for one confirmation:
$CLI -rpcwallet=uvwallet getbalance
```

## 3. Point the CLI at signet and pay

The wallet talks to the node through `--backend signet`; everything else is the
ordinary v2 flow (`demo/local2.sh` is the same sequence on a file-backed chain).

```bash
export UV_BTC_URL=http://127.0.0.1:38332/wallet/uvwallet
export UV_BTC_USER=uv UV_BTC_PASS=uv
# Start scanning at the current tip: there is nothing of ours below it.
# The scan floor now comes from the anchor: `uv issue` stamps the height below
# which the asset cannot have records, and a receiver refuses a chain view that
# starts above it. Setting the floor to the current tip by hand — which this
# guide used to tell you to do — is precisely the fail-open case: a view that
# starts above an earlier conflicting record reports "nothing found", which
# reads as "nothing exists" and accepts a double-spend.
# UV_BTC_SCAN_FROM remains as an override, and may only ever *lower* the floor.
export UV_BTC_FEERATE=2      # sats/vB; a well-fed record confirms before it can be raced

H=~/.uv-signet-demo
cargo build --release -p uv-cli
UV="./target/release/uv --home $H --backend signet"

$UV issue   --wallet alice --amount 1000                    # writes $H/anchor.json
$UV address --wallet bob --slots 8 --out $H/bob.json        # hand over once
$UV send    --wallet alice --to $H/bob.json --amount 300    # real OP_RETURN on signet
# wait for three signet blocks (~30 min), then:
$UV scan    --wallet bob
$UV balance --wallet bob
```

`send` prints the nullifier it published; find the transaction with

```bash
$CLI listtransactions '*' 5
# then look it up: https://mempool.space/signet/tx/<txid>
```

## Notes that cost us time before

- **Fund with a fee rate.** A faucet-sized UTXO cannot pay the wallet's default
  `fallbackfee`; `UV_BTC_FEERATE=2` is what makes a 1,000-sat coin enough.
- **Background runs must be `nohup`'d and log unbuffered to a file.** A plain
  background job dies with the shell, and piping through `tail` buffers
  everything — that combination once destroyed the forensics of a mid-flight
  demo. Ground truth is `getbalance` + `listtransactions`.
- **zsh does not word-split `$C` from `C="cmd -args"`.** Use inline commands or
  a bash array; the silent "no such file or directory" reads exactly like a
  zero balance.
- **Do not hit faucets automatically.** Fund the address by hand.
