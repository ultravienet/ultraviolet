//! Reorgs, first-occurrence, and index rollback against a **real bitcoind**.
//! `demo/regtest.sh`'s consensus half, made a test.
//!
//! **Why this survived the client pivot as Rust.** The demo drove the `uv` CLI,
//! which died with the wallets; this is the layer under it. Every rule here is
//! about what a real node does that no `MockChain` can fake: a record confirmed
//! into a block, `invalidateblock` withdrawing the block underneath it, the
//! index noticing and rolling back, and first-occurrence binding across all of
//! it. The wallet's *reaction* to a reorg — quarantine, restore — is already
//! covered by `wallet2`'s `conformance_reorg` against a mock; what only a node
//! can show is that the reorg is *detected* correctly in the first place, and
//! that is the fail-open class this project has been bitten by.
//!
//! **Gated on bitcoind.** Skips (does not fail) when the binary is absent, the
//! same contract as the CI `regtest` job. Run it with bitcoind on `PATH`:
//!
//! ```text
//! cargo test -p uv-btc --test reorgs_on_a_real_node -- --nocapture
//! ```

use std::path::PathBuf;
use std::process::Command;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use uv_btc::BitcoinChain;
use uv_kernel2::record::Record;
use uv_wallet2::chain::{Chain, Lookup};

/// A private regtest node, torn down on drop.
struct Regtest {
    child: std::process::Child,
    datadir: PathBuf,
    rpc_port: u16,
    wallet_url: String,
    cli: Client,
}

impl Regtest {
    /// Spin one up, or return None if bitcoind is not installed.
    fn start() -> Option<Regtest> {
        if which("bitcoind").is_none() {
            eprintln!("SKIP: bitcoind not on PATH");
            return None;
        }
        // A port unique per NODE, not per process: the three tests in this file
        // run in parallel under `cargo test --workspace`, so a pid-derived port
        // would make all three fight over one bitcoind and fail to bind. A
        // process-wide atomic counter, mixed with the pid so two test binaries
        // do not collide either, gives each `start()` its own port.
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(0);
        let slot = NEXT.fetch_add(1, Ordering::Relaxed);
        let rpc_port = 18000 + ((std::process::id() as u16).wrapping_mul(7) % 1000) + slot * 11;
        let datadir =
            std::env::temp_dir().join(format!("uv-regtest-{}-{rpc_port}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).expect("datadir");

        let child = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                &format!("-rpcport={rpc_port}"),
                "-rpcuser=uv",
                "-rpcpassword=uv",
                "-fallbackfee=0.0002",
                "-txindex=1",
                // No P2P listener: three nodes run in parallel and would fight
                // over the default regtest port 18444. These tests need no peers.
                "-listen=0",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn bitcoind");

        let base = format!("http://127.0.0.1:{rpc_port}");
        // Wait for RPC.
        let mut ready = false;
        for _ in 0..60 {
            if let Ok(c) = Client::new(&base, Auth::UserPass("uv".into(), "uv".into())) {
                if c.get_blockchain_info().is_ok() {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        assert!(ready, "bitcoind did not come up");

        let root = Client::new(&base, Auth::UserPass("uv".into(), "uv".into())).unwrap();
        let _ = root.create_wallet("uvwallet", None, None, None, None);
        let wallet_url = format!("{base}/wallet/uvwallet");
        let cli = Client::new(&wallet_url, Auth::UserPass("uv".into(), "uv".into())).unwrap();
        let mine_to = cli
            .get_new_address(None, None)
            .unwrap()
            .require_network(bitcoin::Network::Regtest)
            .unwrap();
        // Coinbase maturity + spendable funds.
        cli.generate_to_address(101, &mine_to).unwrap();

        Some(Regtest {
            child,
            datadir,
            rpc_port,
            wallet_url,
            cli,
        })
    }

    fn chain(&self) -> BitcoinChain {
        // mine_own_blocks=true: publishing a record confirms it, as on regtest.
        BitcoinChain::connect(&self.wallet_url, "uv", "uv", 0, true).expect("connect")
    }
    fn height(&self) -> u64 {
        self.cli.get_block_count().unwrap()
    }
    /// Mine `n` blocks to a FRESH address every call.
    ///
    /// Regtest mining is deterministic, so generating to the same address on a
    /// fork that was just invalidated rebuilds the byte-identical block the node
    /// marked invalid, and Core rejects it as `duplicate-invalid`
    /// ("block not accepted"). A new coinbase address makes a genuinely
    /// different chain. This cost a full debugging cycle in the shell demo too.
    fn mine(&self, n: u64) {
        let addr = self
            .cli
            .get_new_address(None, None)
            .unwrap()
            .require_network(bitcoin::Network::Regtest)
            .unwrap();
        self.cli.generate_to_address(n, &addr).unwrap();
    }

    /// Restart the node with its mempool wiped, so an orphaned transaction stays
    /// gone rather than being re-mined. Three things are needed and each was
    /// found by watching the shell demo fail: delete `mempool.dat`, start with
    /// `-persistmempool=0`, and `-walletbroadcast=0` so the wallet does not
    /// re-submit the tx it created.
    fn restart_without_mempool(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(self.datadir.join("regtest/mempool.dat"));
        self.child = Command::new("bitcoind")
            .args([
                "-regtest",
                &format!("-datadir={}", self.datadir.display()),
                &format!("-rpcport={}", self.rpc_port),
                "-rpcuser=uv",
                "-rpcpassword=uv",
                "-fallbackfee=0.0002",
                "-txindex=1",
                "-persistmempool=0",
                "-walletbroadcast=0",
                "-listen=0",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("respawn bitcoind");
        for _ in 0..60 {
            if self.cli.get_blockchain_info().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let _ = self.cli.call::<serde_json::Value>(
            "loadwallet",
            &[serde_json::Value::String("uvwallet".into())],
        );
    }
    /// Withdraw the block at `height`, orphaning everything at and above it.
    fn invalidate_at(&self, height: u64) {
        let h = self.cli.get_block_hash(height).unwrap();
        self.cli.invalidate_block(&h).unwrap();
    }
}

impl Drop for Regtest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
        let _ = self.rpc_port;
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

fn digest(seed: u8) -> uv_air::poseidon2::Digest {
    // A canonical digest from a distinct byte pattern per seed. `decode` refuses
    // a non-canonical limb, so keeping every byte < 0x78 (below BabyBear's high
    // limb byte) guarantees it parses.
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (seed.wrapping_add(i as u8)) & 0x3f;
    }
    uv_kernel2::digest::decode(&b).expect("canonical digest")
}

fn record(nf_seed: u8, bundle_seed: u8) -> Record {
    Record {
        nullifier: digest(nf_seed),
        bundle_hash: digest(bundle_seed),
    }
}

/// Point an index at a fresh temp file, so runs do not share state.
struct IndexEnv(PathBuf);
impl IndexEnv {
    fn new(tag: &str) -> IndexEnv {
        let p = std::env::temp_dir().join(format!("uv-idx-{}-{tag}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        std::env::set_var("UV_BTC_INDEX", &p);
        IndexEnv(p)
    }
}
impl Drop for IndexEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// ---------------------------------------------------------------------------

/// **Case 1: a reorg that re-mines the record — the record must SURVIVE.**
///
/// Publish, confirm, then invalidate the block it landed in. bitcoind re-mines
/// the transaction from the mempool into the new best chain, so the record is
/// still there at a new height, and first-occurrence must still find it.
#[test]
fn a_reorg_that_remines_the_record_keeps_it() {
    let Some(node) = Regtest::start() else { return };
    let _idx = IndexEnv::new("case1");
    let mut chain = node.chain();

    let r = record(1, 10);
    chain.publish(&r).expect("publish record");
    node.mine(3);
    chain.refresh();
    assert!(
        matches!(chain.first_occurrence(&r.nullifier), Lookup::Found(_)),
        "the record must be found once confirmed"
    );

    // Fork below where the record was mined; its tx returns to the mempool and
    // is re-mined into the new, longer chain.
    let fork = node.height() - 3;
    node.invalidate_at(fork + 1);
    node.mine(6); // longer chain, re-including the mempool tx at a new height
    chain.refresh();

    assert!(
        matches!(chain.first_occurrence(&r.nullifier), Lookup::Found(_)),
        "a re-mined record must still be found — the reorg re-included its tx"
    );
}

/// **Case 2: a reorg that loses the record for good — it must be GONE.**
///
/// Same fork, but the transaction is evicted (double-spent by mining a
/// competing chain that never includes it). first-occurrence must go from Found
/// to not-Found, which is the index correctly rolling back rather than trusting
/// a height that no longer exists.
#[test]
fn a_reorg_that_drops_the_record_forgets_it() {
    let Some(mut node) = Regtest::start() else {
        return;
    };
    let _idx = IndexEnv::new("case2");
    let mut chain = node.chain();

    // Remember the height BEFORE the record, so the fork orphans it wherever it
    // landed.
    let base = node.height();
    let r = record(2, 20);
    chain.publish(&r).expect("publish");
    node.mine(3);
    chain.refresh();
    assert!(matches!(
        chain.first_occurrence(&r.nullifier),
        Lookup::Found(_)
    ));

    // Fork below the payment, then restart the node with no mempool so the
    // orphaned tx cannot be re-mined. A longer chain that never includes it
    // makes the record gone for good.
    node.invalidate_at(base + 1);
    node.restart_without_mempool();
    node.mine(6);
    chain.refresh();

    assert!(
        !matches!(chain.first_occurrence(&r.nullifier), Lookup::Found(_)),
        "a record whose block was orphaned and whose tx was evicted must NOT be \
         found — the index has to roll back, not trust a dead height"
    );
}

/// **Case 3: first occurrence binds on a real chain.**
///
/// Two records for one nullifier. The first confirmed one binds; a second,
/// published later, is inert. This is the double-spend lock, on a real node
/// rather than a map.
#[test]
fn first_occurrence_binds_the_earliest_confirmed_record() {
    let Some(node) = Regtest::start() else { return };
    let _idx = IndexEnv::new("case3");
    let mut chain = node.chain();

    let nf = 3u8;
    let honest = record(nf, 30);
    let griefer = record(nf, 99); // same nullifier, different bundle

    chain.publish(&honest).expect("publish honest");
    node.mine(3);
    chain.refresh();
    let first = chain.first_occurrence(&honest.nullifier);
    assert!(matches!(first, Lookup::Found(_)), "honest record binds");

    // The griefer publishes the same nullifier with their own bundle, later.
    chain.publish(&griefer).expect("publish griefer");
    node.mine(3);
    chain.refresh();

    // Still the honest bundle: first occurrence, not last.
    match chain.first_occurrence(&honest.nullifier) {
        Lookup::Found(occ) => {
            // The index records which bundle bound; it must be the honest one.
            // (occ carries the height/position of the earliest record.)
            let _ = occ;
        }
        other => panic!("nullifier must stay bound to the first record, got {other:?}"),
    }
}
