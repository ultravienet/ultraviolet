//! `uv` — the Ultraviolet CLI wallet, on the sovereign STARK.
//!
//! ```text
//! uv --home DIR issue     --wallet alice --amount 1000        # genesis + trust anchor
//! uv --home DIR address   --wallet bob --slots 16 --out b.json # hand over once
//! uv --home DIR send      --wallet alice --to b.json --amount 300
//! uv --home DIR scan      --wallet bob                        # verify + ingest
//! uv --home DIR balance   --wallet bob
//! uv --home DIR reconcile --wallet bob                        # after a reorg
//! uv --home DIR status    --wallet bob                        # what the chain sees
//! ```
//!
//! **An address is a batch of one-time slots.** Each slot is everything a payer
//! needs to build one note — and nothing that lets the payer spend it or watch
//! it, because a note commits to a spend *anchor* rather than to the key behind
//! it (spec/02). Hand the batch over once; after that the payee can be offline
//! and no payment needs an invoice.
//!
//! It is not fully non-interactive, and spec/02 used to claim it was. Removing
//! the handover entirely needs one long-lived anchor per address, which puts a
//! long-lived secret in every spend's witness — deliberately not taken, and
//! gated on the circuit review (spec/99 [AUDIT]).
//!
//! Bundles are sealed to the payee's scan key (hybrid ML-KEM-768 + X25519)
//! before they are mailed, and a scan finds its own mail by trial
//! decapsulation — there is no addressee to leak. What still travels in the
//! clear is the *address* itself and `anchor.json`, both of which are public
//! but **unauthenticated**, which is why the handover wants a carrier that
//! authenticates it (spec/99 [SIGNAL]).
//!
//! The trust anchor is likewise explicit: `issue` writes the issuance
//! commitment to `anchor.json`, and receivers validate lineages against it.
//! Issuance policy — who may mint an asset, how the anchor is published, and
//! whether anyone can check the supply — is spec/99 `[SUPPLY]`.

use uv_cli::transport::{Directory, Relay, SignalCli, Transport};

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use uv_air::prove::{hiding_config, HidingConfig, Vouched};
use uv_air::wots::Digest;
use uv_btc::BitcoinChain;
use uv_kernel2::amount::Amount;
use uv_kernel2::digest;
use uv_kernel2::keys::WalletSeed;
use uv_wallet2::chain::{Chain, FileChain};
use uv_wallet2::reconcile::{reconcile, Genesis};
use uv_wallet2::send::{broadcast, prepare, rebroadcast, Recipient, WalletCtx};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::Store;

/// The hiding prover's configuration. Blinding comes from the operating system
/// on every call — see `uv_air::prove::hiding_config`, which explains why a
/// fixed seed here was a real break of the confidentiality this buys.
fn prover_config() -> Vouched<HidingConfig> {
    hiding_config()
}

#[derive(Parser)]
#[command(name = "uv", about = "Ultraviolet CLI wallet")]
struct Cli {
    /// Shared data directory (wallets, the demo chain, the mailbox, the anchor).
    #[arg(long, global = true, default_value = "./uv-data")]
    home: PathBuf,
    /// Chain backend: `mock` (file-backed), `regtest`, or `signet`.
    #[arg(long, global = true, default_value = "mock")]
    backend: String,
    /// How bundles travel: `dir` (a local drop box), `relay` (over the network,
    /// see `UV_RELAY_URL`), or `signal` (a linked signal-cli daemon, see
    /// `UV_SIGNAL_URL` / `UV_SIGNAL_TO`). Defaults to `dir`, so nothing that
    /// worked before behaves differently.
    #[arg(long, global = true, default_value = "dir")]
    transport: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Issue an asset into a wallet, and write the trust anchor.
    Issue {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        amount: u64,
    },
    /// Publish an address: a batch of unused payment slots.
    Address {
        #[arg(long)]
        wallet: String,
        /// How many slots to issue. Each is good for exactly one payment.
        #[arg(long, default_value_t = 16)]
        slots: u64,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Who this batch is for. **Give each counterparty their own batch.**
        /// Slot reservations are tracked by the payer, so two payers holding
        /// one address both start at slot 0 and one of them ends up with a
        /// payment that has nowhere to sit (spec/99 [SLOT-COLLISION]).
        /// Recording the recipient is what makes replenishment answerable and
        /// a collision diagnosable.
        #[arg(long = "for")]
        peer: Option<String>,
    },
    /// Export or install the trust anchor a payee needs in order to validate.
    Anchor {
        #[command(subcommand)]
        what: AnchorCmd,
    },
    /// Pay an address: take its next unused slot, prove the hop, publish the
    /// record, mail the bundle.
    Send {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        amount: u64,
        /// Fund from this exact note commitment (hex) instead of picking one.
        /// Used to demonstrate that a conforming wallet cannot double-spend:
        /// pointing `send` at an already-spent note replays its logged payload
        /// rather than signing a second one.
        #[arg(long)]
        from: Option<String>,
    },
    /// Verify incoming bundles against the anchor and ingest what checks out.
    Scan {
        #[arg(long)]
        wallet: String,
    },
    /// Spendable balance.
    Balance {
        #[arg(long)]
        wallet: String,
    },
    /// Re-validate held notes against the chain (run after a reorg).
    Reconcile {
        #[arg(long)]
        wallet: String,
    },
    /// What each operation costs in bitcoin — and what costs nothing.
    Fees {
        /// Price at this rate instead of asking the node, in sats per vByte.
        #[arg(long)]
        rate: Option<u64>,
    },
    /// Add up every issuance record on the chain, per asset.
    Supply {
        /// Report only this asset. Possible because the record now carries the
        /// asset id in the clear — the previous 44-byte record hashed it, and
        /// a one-way hash cannot be filtered on.
        #[arg(long)]
        asset: Option<String>,
    },
    /// What this wallet and its chain view actually see right now.
    Status {
        #[arg(long)]
        wallet: String,
    },
    /// Advance the demo chain (mock backend only).
    Mine {
        #[arg(long, default_value_t = 1)]
        blocks: u64,
    },
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Print (or write) this home's anchor, for handing to a payee.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Install an anchor received from an issuer.
    Import {
        #[arg(long)]
        from: PathBuf,
    },
}

// ---- persistence ----
//
// The wallet file format lives in `uv-app` (`wallet::open_or_create` / `save`),
// because the phone opens the same file and two readers of a file holding the
// sign-log is how they drift. This layer only supplies the passphrase flow —
// a terminal prompts; an app has a lock screen.

// The address and bundle wire types live in `uv-app` (`address`, `bundle`) —
// the two halves of the payer↔payee wire, spoken identically by the CLI and
// the phone. Two definitions of either is how the ends drift.
use uv_app::address::Address;

fn anchor_path(home: &Path) -> PathBuf {
    home.join("anchor.json")
}
fn mailbox(home: &Path, wallet: &str) -> PathBuf {
    home.join("mailbox").join(wallet)
}

/// Build the carrier this invocation should use.
///
/// Exits rather than falling back: a payer who asked for a relay and silently
/// got a local directory would believe a payment had been sent when it had gone
/// nowhere the payee can reach.
fn make_transport(kind: &str, home: &Path, wallet: &str) -> Box<dyn Transport> {
    match kind {
        "dir" => Box::new(Directory {
            inbox: mailbox(home, "inbox"),
        }),
        "relay" => {
            let url = std::env::var("UV_RELAY_URL").unwrap_or_else(|_| {
                eprintln!("--transport relay needs UV_RELAY_URL (e.g. http://host:8787)");
                std::process::exit(1);
            });
            Box::new(Relay {
                url,
                // Per wallet: two wallets in one home each track their own
                // position, or one wallet's fetch would hide the other's mail.
                cursor_path: home.join(format!("relay-cursor-{wallet}.txt")),
            })
        }
        "signal" => {
            let to = std::env::var("UV_SIGNAL_TO").unwrap_or_else(|_| {
                eprintln!("--transport signal needs UV_SIGNAL_TO (the payee's number,");
                eprintln!("or your own for Note-to-Self). See demo/signal.md.");
                std::process::exit(1);
            });
            // signal-cli's own data directory, which is where it writes the
            // attachments it downloads. Overridable because `--config` moves it.
            let base = std::env::var("UV_SIGNAL_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                    PathBuf::from(home).join(".local/share/signal-cli")
                });
            Box::new(SignalCli {
                url: std::env::var("UV_SIGNAL_URL")
                    .unwrap_or_else(|_| "http://127.0.0.1:8080".into()),
                recipient: to,
                attachments: base.join("attachments"),
                // Per wallet, like the relay cursor: two wallets in one home
                // must not consume each other's mail.
                seen_path: home.join(format!("signal-seen-{wallet}.txt")),
                outbox: home.join("signal-outbox"),
            })
        }
        other => {
            eprintln!("unknown transport {other:?}; use `dir`, `relay` or `signal`");
            std::process::exit(1);
        }
    }
}

fn hexd(d: &Digest) -> String {
    hex::encode(digest::encode(d))
}
fn unhexd(s: &str) -> Digest {
    try_unhexd(s).expect("canonical digest")
}

/// The fallible form. Anything that came from a counterparty's file goes
/// through this: `unhexd` panics, and a panic on a payee's address used to
/// happen *after* slots were reserved, so one malformed field burnt every slot
/// in a multi-note plan.
fn try_unhexd(s: &str) -> Option<Digest> {
    let v = hex::decode(s).ok()?;
    let a: [u8; 32] = v.as_slice().try_into().ok()?;
    digest::decode(&a)
}

/// The passphrase for wallet files, asked **at most once per process**.
///
/// `UV_PASSPHRASE` for scripts and CI; a prompt otherwise. Set it to the empty
/// string to store wallets in the clear — allowed, but it has to be asked for.
///
/// **Why it is cached, and why that is a correctness fix rather than a
/// convenience.** This used to prompt independently on load and on save, and
/// the two answers were never compared. Typing it wrong the second time did
/// not fail: it silently re-keyed the wallet to the typo, and the file could
/// never be opened again with the passphrase its owner believed it had. There
/// is no recovery from that — the seed is inside.
///
/// Caching also removes an interactive prompt from a place it must never be:
/// `broadcast`'s persist step runs between "signed" and "on Bitcoin", and a
/// prompt there stalls a payment mid-flight waiting for a human.
static PASSPHRASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn ask_passphrase(prompt: &str) -> Option<String> {
    if let Ok(p) = std::env::var("UV_PASSPHRASE") {
        return if p.is_empty() { None } else { Some(p) };
    }
    match rpassword::prompt_password(prompt) {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    }
}

/// Opening an existing wallet: ask once, remember the answer. A wrong answer
/// is caught immediately by the AEAD, so there is nothing to confirm against.
fn passphrase_for_open() -> Option<String> {
    PASSPHRASE
        .get_or_init(|| ask_passphrase("wallet passphrase (empty = unencrypted): "))
        .clone()
}

/// Writing a wallet. Reuses whatever opened it, so a save can never disagree
/// with a load. Only a *new* wallet reaches the prompt here — and that one is
/// asked twice, because there is no existing file to check a typo against.
fn passphrase_for_save() -> Option<String> {
    if let Some(cached) = PASSPHRASE.get() {
        return cached.clone();
    }
    let chosen = {
        let first = ask_passphrase("choose a wallet passphrase (empty = unencrypted): ");
        if first.is_some() && std::env::var("UV_PASSPHRASE").is_err() {
            let again = ask_passphrase("confirm passphrase: ");
            if again != first {
                eprintln!("passphrases do not match; nothing was written");
                std::process::exit(1);
            }
        }
        first
    };
    // Another thread may have raced us; `get_or_init` returns the winner and
    // we use that, so one process can never hold two different passphrases.
    PASSPHRASE.get_or_init(|| chosen).clone()
}

/// Open (or create) the wallet through `uv-app`'s single reader, prompting for
/// a passphrase only when the file on disk is actually sealed — asking for one
/// that is not needed teaches people to type it where it is not wanted.
fn load_wallet(home: &Path, name: &str) -> (WalletSeed, Store, SignLog) {
    let pw = match uv_app::wallet::sealing(home, name) {
        Ok(uv_app::wallet::Sealing::Sealed) => passphrase_for_open(),
        // Absent or plain needs no passphrase; a probe error (bad magic, an
        // unreadable file) is reported by `open_or_create` with the full
        // explanation, so it is not duplicated here.
        _ => None,
    };
    match uv_app::wallet::open_or_create(home, name, pw.as_deref()) {
        Ok(w) => (w.seed, w.store, w.log),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Save, panicking on failure. For call sites where nothing is in flight and a
/// write failure is simply fatal.
fn save_wallet(home: &Path, name: &str, seed: &WalletSeed, store: &Store, log: &SignLog) {
    try_save_wallet(home, name, seed, store, log).unwrap_or_else(|e| panic!("{e}"));
}

/// Save, reporting failure. Used as `broadcast`'s persist step, where a failed
/// write must stop the publish rather than take the process down after it: the
/// spend is signed by then, and the only safe states are "logged and published"
/// or "logged and not published". "Published but not logged" is the one that
/// discloses a one-time key on retry.
fn try_save_wallet(
    home: &Path,
    name: &str,
    seed: &WalletSeed,
    store: &Store,
    log: &SignLog,
) -> Result<(), String> {
    // `uv-app` writes atomically (temp file + rename): a crash mid-write must
    // not truncate the file that holds the sign-log. This CLI kept writing in
    // place for a while after that fix landed in `uv-app` — two writers of one
    // format is how one of them stays wrong, which is why it now has one.
    uv_app::wallet::save(
        home,
        name,
        seed,
        store,
        log,
        passphrase_for_save().as_deref(),
    )
    .map_err(|e| e.to_string())
}

fn make_chain(backend: &str, home: &Path) -> Box<dyn Chain> {
    match backend {
        "regtest" | "signet" => {
            let url = std::env::var("UV_BTC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:18443/wallet/uvwallet".to_string());
            let user = std::env::var("UV_BTC_USER").unwrap_or_else(|_| "uv".to_string());
            let pass = std::env::var("UV_BTC_PASS").unwrap_or_else(|_| "uv".to_string());
            // The floor comes from the anchor: the height below which this
            // asset cannot have records. `UV_BTC_SCAN_FROM` remains as an
            // override, but may only ever *lower* it — a floor set above an
            // earlier conflicting record makes a double-spend look valid, and
            // this guide used to tell people to set it to the current tip.
            let anchor_floor: u64 = std::fs::read(anchor_path(home))
                .ok()
                .and_then(|b| serde_json::from_slice::<Anchor>(&b).ok())
                .and_then(|a| a.issued_below)
                .unwrap_or(0);
            let scan_from = match std::env::var("UV_BTC_SCAN_FROM")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
            {
                Some(env) => env.min(anchor_floor),
                None => anchor_floor,
            };
            Box::new(
                BitcoinChain::connect(&url, &user, &pass, scan_from, backend == "regtest")
                    .expect("connect to bitcoind"),
            )
        }
        _ => Box::new(FileChain::open(home.join("chain.json"))),
    }
}

fn main() {
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.home).expect("mkdir home");
    match cli.cmd {
        Cmd::Issue { wallet, amount } => cmd_issue(&cli.home, &cli.backend, &wallet, amount),
        Cmd::Address {
            wallet,
            slots,
            out,
            peer,
        } => cmd_address(&cli.home, &wallet, slots, out, peer.as_deref()),
        Cmd::Send {
            wallet,
            to,
            amount,
            from,
        } => cmd_send(
            &cli.home,
            &cli.backend,
            &cli.transport,
            &wallet,
            &to,
            amount,
            from.as_deref(),
        ),
        Cmd::Scan { wallet } => cmd_scan(&cli.home, &cli.backend, &cli.transport, &wallet),
        Cmd::Balance { wallet } => cmd_balance(&cli.home, &wallet),
        Cmd::Reconcile { wallet } => cmd_reconcile(&cli.home, &cli.backend, &wallet),
        Cmd::Status { wallet } => cmd_status(&cli.home, &cli.backend, &wallet),
        Cmd::Fees { rate } => cmd_fees(&cli.backend, &cli.home, rate),
        Cmd::Supply { asset } => cmd_supply(&cli.home, &cli.backend, asset),
        Cmd::Anchor { what } => match what {
            AnchorCmd::Export { out } => cmd_anchor_export(&cli.home, out),
            AnchorCmd::Import { from } => cmd_anchor_import(&cli.home, &from),
        },
        Cmd::Mine { blocks } => {
            // Refuse rather than mine a phantom. This ignored `--backend` and
            // always advanced the file-backed demo chain, so
            // `uv --backend signet mine` printed a tip that described nothing —
            // a number that looks like the state of Bitcoin and is not.
            if cli.backend != "mock" {
                eprintln!(
                    "`mine` only exists for the mock backend; blocks on {} come from \
                     the network",
                    cli.backend
                );
                eprintln!("(on regtest, mine with `bitcoin-cli generatetoaddress`)");
                std::process::exit(1);
            }
            let mut c = FileChain::open(cli.home.join("chain.json"));
            c.mine(blocks);
            match c.tip() {
                Ok(t) => println!("tip {t}"),
                Err(e) => println!("tip unavailable ({e})"),
            }
        }
    }
}

// The trust anchor's type and its file live in `uv-app` — the phone reads the
// same anchor.json with the same refusals, and two parsers of the trust root
// would be two chances to disagree about what "trusted" means.
use uv_app::anchor::Anchor;

fn cmd_issue(home: &Path, backend: &str, wallet: &str, amount: u64) {
    // The ordering discipline lives in `uv-app`: `prepare_issue` (floor
    // preflight, note into the wallet) → SAVE → `publish_issue` (record to
    // Bitcoin, anchor written last). The type makes the sequence hard to write
    // wrongly; this layer supplies persistence and words.
    let (seed, store, log) = load_wallet(home, wallet);
    let mut w = uv_app::wallet::Wallet { seed, store, log };
    let mut chain = make_chain(backend, home);

    let prepared =
        uv_app::commands::prepare_issue(&mut w, chain.as_ref(), amount).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });
    save_wallet(home, wallet, &w.seed, &w.store, &w.log);

    let issued =
        uv_app::commands::publish_issue(chain.as_mut(), home, prepared).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });
    println!("issued {} to {wallet}", issued.amount);
    println!("asset      {}", issued.asset_hex);
    println!("anchor     {}", issued.commitment_hex);
    println!("(receivers validate every lineage against this anchor)");
}

// The batch ledger (which slot ranges went to whom) lives in `uv-app`, beside
// the other sidecar files both callers read.

/// Price every operation, including the ones that are free.
///
/// The free list is the point. "What does a transaction cost" is the question
/// people ask; "what costs nothing" is the one whose answer surprises them, and
/// leaving it out is how a reader concludes that receiving must cost something
/// because it does everywhere else.
fn cmd_fees(backend: &str, home: &Path, rate: Option<u64>) {
    let (rate, source) = match rate {
        Some(r) => (r, "--rate"),
        None => match backend {
            "regtest" | "signet" => {
                // Ask the node the same question a publication asks.
                let chain = make_chain(backend, home);
                match chain.tip() {
                    Ok(_) => (btc_feerate(backend, home), "from your node"),
                    Err(_) => (2, "node unreachable — the fallback a publication would use"),
                }
            }
            _ => (2, "no node on this backend; the published fallback"),
        },
    };
    print!("{}", uv_cli::fees::report(rate, source));
}

/// The node's rate, via the same path `publish` takes.
fn btc_feerate(backend: &str, home: &Path) -> u64 {
    let _ = home;
    let url = std::env::var("UV_BTC_URL").unwrap_or_else(|_| {
        if backend == "signet" {
            "http://127.0.0.1:38332/wallet/uvwallet".to_string()
        } else {
            "http://127.0.0.1:18443/wallet/uvwallet".to_string()
        }
    });
    let user = std::env::var("UV_BTC_USER").unwrap_or_else(|_| "uv".to_string());
    let pass = std::env::var("UV_BTC_PASS").unwrap_or_else(|_| "uv".to_string());
    match uv_btc::BitcoinChain::connect(&url, &user, &pass, 0, false) {
        Ok(c) => c.feerate_sat_vb(),
        Err(_) => 2,
    }
}

/// What was issued, read off Bitcoin. **Exact, not a bound.**
///
/// The previous version of this command could only report a chain-wide sum over
/// every asset and every stranger, and had to label it an upper bound. The
/// reason was one design detail: the record carried
/// `H(asset ‖ commitment ‖ amount)`, and a one-way hash cannot be enumerated —
/// a holder could find their own issuance but nobody could ask which records
/// belonged to an asset. The record now carries the asset and the genesis
/// commitment in the clear, so `--asset X` filters and sums, and the answer is
/// the total.
///
/// **The one residual, reported rather than buried.** Nothing authenticates a
/// record's asset id, so a stranger can publish a *decoy* bearing someone
/// else's asset. It creates no spendable coin — nobody holds a note opening to
/// their commitment — but it does bear the id. So records are split into
/// **attested** (accounted for by this home's anchor) and **unattested**, and
/// the two are never added together. Closing that entirely is the mint
/// signature, which is spec/12's reissuance work and is not built.
fn cmd_supply(home: &Path, backend: &str, asset_filter: Option<String>) {
    // The counting, the attestation split, and the refresh-first rule live in
    // `uv-app` (`commands::supply`); this layer formats and explains.
    let chain = make_chain(backend, home);
    let s = uv_app::commands::supply(home, chain.as_ref(), asset_filter.as_deref());

    if s.assets.is_empty() {
        match asset_filter.as_deref() {
            Some(want) => {
                let want = want.to_ascii_lowercase();
                println!("no issuance records for asset {want} on this chain view");
                println!("  either that asset was never issued here, or this view does not reach");
                println!("  far enough back (`uv status` reports the view's floor)");
            }
            None => {
                println!("no issuance records on this chain view");
                println!(
                    "  either nothing was issued, or this view does not reach far enough back"
                );
                println!("  (`uv status` reports the view's floor)");
            }
        }
        return;
    }

    let mut any_unattested = false;
    for a in &s.assets {
        println!("asset {}", a.asset_hex);
        for r in &a.records {
            println!(
                "  {:>20}  genesis {}  {}",
                r.amount,
                r.commitment_hex,
                if r.attested { "attested" } else { "unattested" }
            );
        }
        let unattested = a.total - a.attested;
        if unattested == 0 {
            println!(
                "  issued: {}  (every record attested by this home's anchor)",
                a.total
            );
        } else if a.attested == 0 {
            println!("  issued: {}  — NONE attested by this home", a.total);
            any_unattested = true;
        } else {
            println!(
                "  issued: {}  = {} attested + {} unattested",
                a.total, a.attested, unattested
            );
            any_unattested = true;
        }
        println!();
    }

    println!("Read off Bitcoin, and exact: every coin of an asset descends from one of its");
    println!("records, because a lineage whose genesis is unpublished is refused and");
    println!("conservation is proven at every hop. Nothing off-chain can add to these.");
    if any_unattested {
        println!();
        println!("UNATTESTED records bear an asset id this home cannot vouch for. Nothing");
        println!("authenticates an id, so anyone may publish one — it creates no spendable");
        println!("coin, since no one holds a note opening to its genesis, but it does inflate");
        println!("the figure above. Attested and unattested are kept apart for that reason.");
    }
}

fn cmd_anchor_export(home: &Path, out: Option<PathBuf>) {
    let bytes = std::fs::read(anchor_path(home)).unwrap_or_else(|_| {
        eprintln!("no anchor.json in this home — only the issuer has one to export");
        std::process::exit(1);
    });
    match out {
        Some(p) => {
            std::fs::write(&p, &bytes).expect("write anchor");
            println!("anchor written to {}", p.display());
            println!("a payee cannot validate anything without this — hand it over with the");
            println!("address. It is public, but it is NOT authenticated: an anchor from the");
            println!("wrong hands makes a forged lineage look valid, so get it from the issuer.");
        }
        None => print!("{}", String::from_utf8_lossy(&bytes)),
    }
}

fn cmd_anchor_import(home: &Path, from: &Path) {
    // Every refusal — the mandatory genesis opening, canonical digests, the
    // different-asset and same-asset-different-genesis conflicts, the
    // floor-merged-downward rule — lives in `uv-app` (`anchor::{parse,
    // import}`), because the phone imports anchors too and a silent
    // replacement there is the same supply bug.
    let bytes = std::fs::read(from).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", from.display());
        std::process::exit(1);
    });
    let incoming = uv_app::anchor::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let asset_hex = incoming.asset_hex.clone();
    let floor = incoming.issued_below;
    match uv_app::anchor::import(home, incoming) {
        Ok(uv_app::anchor::ImportOutcome::Installed) => {
            println!("anchor installed: asset {asset_hex}");
            match floor {
                Some(h) => println!("this asset has no records below height {h}"),
                None => {
                    println!("no issuance floor recorded — a narrow chain view cannot be checked")
                }
            }
        }
        Ok(uv_app::anchor::ImportOutcome::FloorMergedDown {
            had,
            incoming,
            kept,
        }) => {
            eprintln!("note: issuance floors differ ({had:?} vs {incoming:?}); keeping the safer {kept:?}");
            println!("anchor updated (floor merged downward)");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn cmd_address(home: &Path, wallet: &str, count: u64, out: Option<PathBuf>, peer: Option<&str>) {
    // Slot derivation and the batch-before-handover ordering live in `uv-app`
    // (`commands::make_address`) — the phone shows an address from the same
    // code, and a second implementation is a second way to hand one batch to
    // two payers.
    let (seed, store, log) = load_wallet(home, wallet);
    let mut w = uv_app::wallet::Wallet { seed, store, log };
    let address =
        uv_app::commands::make_address(home, wallet, &mut w, count, peer).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });
    save_wallet(home, wallet, &w.seed, &w.store, &w.log);

    let json = serde_json::to_vec_pretty(&address).unwrap();
    if let Some(p) = out {
        std::fs::write(&p, &json).expect("write address");
        println!("address with {count} slots written to {}", p.display());
        match peer {
            Some(who) => println!("hand this to {who} — and to nobody else."),
            None => println!(
                "hand this to ONE counterparty. Giving the same batch to two payers means \
                 both start at slot 0 (--for records who got it)."
            ),
        }
        println!("each slot pays once, no amount fixed in advance");
    } else {
        println!("{}", String::from_utf8(json).unwrap());
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_send(
    home: &Path,
    backend: &str,
    transport_kind: &str,
    wallet: &str,
    to: &Path,
    amount: u64,
    from: Option<&str>,
) {
    // Planning and every refusal gate live in `uv-app` (`commands::plan_send`):
    // select once, partition replays out before reserving, validate every slot
    // and the scan key before reserving, reserve before publishing. What stays
    // here is what differs between callers — persistence, the carrier, words.
    let address: Address =
        serde_json::from_slice(&std::fs::read(to).expect("read address")).expect("address json");
    let (mut seed, mut store, mut log) = load_wallet(home, wallet);
    let mut chain = make_chain(backend, home);
    let cfg = prover_config();
    // Spending a note whose ancestry was just orphaned is the loss case, so
    // this matters here at least as much as in `scan`.
    reconcile_if_chain_rolled_back(home, wallet, &*chain, &seed, &mut store, &log);

    let from_digest = from.map(unhexd);
    let plan = {
        let w = uv_app::wallet::Wallet { seed, store, log };
        let plan = uv_app::commands::plan_send(home, &w, &address, amount, from_digest.as_ref())
            .unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
        let uv_app::wallet::Wallet {
            seed: s,
            store: st,
            log: l,
        } = w;
        seed = s;
        store = st;
        log = l;
        plan
    };

    let anchor = uv_app::anchor::read(home)
        .ok()
        .flatten()
        .expect("plan_send verified the anchor exists");
    let asset = unhexd(&anchor.asset_hex);

    if plan.parts.len() > 1 {
        let parts: Vec<String> = plan.parts.iter().map(|v| v.to_string()).collect();
        println!(
            "no single note covers {amount}; paying as {} notes ({})",
            plan.parts.len(),
            parts.join(" + ")
        );
    }

    let carrier = make_transport(transport_kind, home, wallet);
    let mut published = 0usize;

    // Rebroadcasts first, and separately, because they are not this payment.
    // Each one re-publishes bytes some earlier command already signed, paying
    // whoever that command paid. Nothing here is mailed and no slot is spent.
    for input in &plan.replays {
        let key_index = store.get(input).expect("selected from the store").key_index;
        let sent = rebroadcast(&mut *chain, &log, key_index)
            .unwrap_or_else(|e| {
                eprintln!("could not rebroadcast: {e:?}");
                std::process::exit(1);
            })
            .expect("partitioned as a replay, so the log holds it");
        println!(
            "note {} was already spent — REBROADCAST its original spend, byte for byte",
            &hexd(input)[..16]
        );
        println!("  nf {}", hexd(&sent.transfer.nullifier));
        println!("  the identical proof reused, no slot spent, nothing mailed");
        println!("  it pays whoever the original payment paid, who already has the bundle");
    }
    if !plan.replays.is_empty() && plan.fresh.is_empty() {
        println!("nothing new to send: every selected note had already been spent");
        return;
    }

    for (input, part, req) in &plan.fresh {
        let recipient = Recipient {
            nullifier_anchor: unhexd(&req.nullifier_anchor_hex),
            randomness: unhexd(&req.randomness_hex),
        };
        // Sign and log, but do not broadcast — `prepare` takes no chain and
        // cannot. The wallet is persisted between here and the broadcast
        // below: a signature that reaches Bitcoin before it reaches disk is a
        // signature a crashed wallet will make again with a different slot.
        let prepared = prepare(
            &cfg,
            WalletCtx {
                store: &mut store,
                log: &mut log,
                seed: &seed,
            },
            input,
            &recipient,
            Amount(*part),
        )
        .unwrap_or_else(|e| {
            eprintln!("send refused: {e:?}");
            eprintln!(
                "{published} of {} records already published",
                plan.fresh.len()
            );
            save_wallet(home, wallet, &seed, &store, &log);
            std::process::exit(1);
        });
        let sent = broadcast(&mut *chain, prepared, || {
            try_save_wallet(home, wallet, &seed, &store, &log)
        })
        .unwrap_or_else(|e| {
            eprintln!("could not publish: {e:?}");
            eprintln!(
                "the spend is signed — re-run the same command to rebroadcast \
                 the identical payload; do not build a new one"
            );
            std::process::exit(1);
        });
        debug_assert!(!sent.replayed, "replays were partitioned out above");
        println!("proved the hop (hiding STARK, ~0.25 s)");

        let mut lineage = store
            .get(input)
            .map(|h| h.lineage.clone())
            .unwrap_or_default();
        lineage.push(sent.hop.clone());
        // The scan key was probe-sealed before anything was reserved, so this
        // cannot fail on a malformed key — but the record is already on
        // Bitcoin here, which is exactly where an abort costs the most, so a
        // failure still gets a diagnosis instead of a panic.
        let (name, wire) = uv_app::commands::seal_bundle(
            &address.scan,
            req.index,
            *part,
            &hexd(&asset),
            lineage,
            &sent.transfer.nullifier,
        )
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            eprintln!(
                "the record IS published and the spend is saved — the money is \
                 not lost, but the bundle was not mailed. The scan key passed \
                 its pre-flight probe, so this should be unreachable; a re-run \
                 will rebroadcast the record and cannot re-mail. Keep the \
                 wallet directory and report this."
            );
            std::process::exit(1);
        });
        // The record is already on Bitcoin, so a carrier that will not take the
        // bundle costs delivery and not money.
        println!("record published: nf {}", hexd(&sent.transfer.nullifier));
        match carrier.put(&name, &wire) {
            Ok(()) => println!("bundle mailed:   {name} via {}", carrier.describe()),
            Err(e) => {
                println!("BUNDLE NOT MAILED: {e}");
                println!("  the payment IS settled — this is delivery, not money. Re-run the");
                println!("  same command once the carrier is back: the record rebroadcasts");
                println!("  harmlessly and the bundle goes out with it.");
            }
        }
        published += 1;
    }

    if plan.fresh.len() > 1 {
        println!(
            "paid {amount} as {} notes; {published} records published, {} slots consumed",
            plan.fresh.len(),
            plan.fresh.len()
        );
    }
}

/// Where a wallet remembers the rollback epoch it last reconciled at.
///
/// A sidecar file, deliberately not a field in the wallet. The wallet is read
/// with plain `bincode` and an `.expect(...)`, and bincode is not
/// self-describing, so adding a field there would panic on every wallet that
/// already exists.
fn epoch_path(home: &Path, wallet: &str) -> PathBuf {
    home.join(format!("reconciled-epoch-{wallet}.json"))
}

/// Reconcile first if the chain has rolled back since this wallet last looked.
///
/// Called before anything that depends on held notes being valid. A wallet that
/// spends a note whose ancestry was just orphaned is the loss case, so `send`
/// needs this as much as `scan` does.
/// The anchor's opening, in the shape `reconcile` wants.
///
/// Returns the parts rather than a `Genesis`, because `Genesis` borrows and a
/// function cannot hand back references into its own locals. The caller keeps
/// these alive and builds the borrow itself — clumsier at two call sites than
/// a lifetime would be, and it keeps the anchor-reading in one place, which is
/// what stops the two paths disagreeing about what this wallet's asset is.
fn genesis_parts(home: &Path) -> Option<(Digest, Digest, u64)> {
    // Through the one anchor reader in `uv-app`. An unreadable anchor yields
    // None here — reconcile then runs without the genesis half, same as a home
    // that has no anchor — because refusing to reconcile at all would leave a
    // wallet unable to react to a reorg over a side file's syntax error.
    let a = uv_app::anchor::read(home).ok().flatten()?;
    Some((
        unhexd(&a.asset_hex),
        unhexd(&a.commitment_hex),
        a.genesis.amount,
    ))
}

fn reconcile_if_chain_rolled_back(
    home: &Path,
    wallet: &str,
    chain: &(impl uv_wallet2::chain::Chain + ?Sized),
    seed: &WalletSeed,
    store: &mut Store,
    log: &SignLog,
) {
    // Detection is lazy — it lives inside a lookup — so the view must be
    // brought up to date before its epoch means anything. Without this the
    // wallet reads last invocation's epoch and is permanently one command
    // behind the chain.
    chain.refresh();
    let now = chain.rollback_epoch();
    let last: u64 = std::fs::read(epoch_path(home, wallet))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(0);
    if now == last {
        return;
    }
    println!("the chain rolled back since this wallet last checked; re-validating");
    // The genesis half. A reorg can orphan the issuance itself, and a note
    // whose issuance is no longer on chain is not money however well its own
    // hops settled.
    let parts = genesis_parts(home);
    let genesis = parts.as_ref().map(|(a, c, amt)| Genesis {
        asset: a,
        commitment: c,
        amount: *amt,
    });
    let out = reconcile(chain, store, log, genesis.as_ref());
    if !out.quarantined.is_empty() {
        println!("{} note(s) quarantined:", out.quarantined.len());
        for c in &out.quarantined {
            println!("  {}", hex::encode(c));
        }
    }
    if !out.restored.is_empty() {
        println!("{} note(s) released from quarantine", out.restored.len());
    }
    if !out.unverifiable.is_empty() {
        println!(
            "{} note(s) COULD NOT BE CHECKED — state unchanged",
            out.unverifiable.len()
        );
    }
    save_wallet(home, wallet, seed, store, log);
    let _ = std::fs::write(epoch_path(home, wallet), serde_json::to_vec(&now).unwrap());
}

fn cmd_scan(home: &Path, backend: &str, transport_kind: &str, wallet: &str) {
    // Every rule of receiving — trial-decapsulation, whole-lineage acceptance,
    // keep-on-transient, discard-on-permanent, set-aside-on-collision, and the
    // durable-before-irreversible ordering — lives in `uv-app`
    // (`commands::scan_inbox`). This layer fetches mail, persists, and speaks.
    let anchor = match uv_app::anchor::read(home) {
        Ok(Some(a)) => a,
        Ok(None) => {
            eprintln!("no anchor.json — nothing to validate against");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let (seed, mut store, log) = load_wallet(home, wallet);
    let chain = make_chain(backend, home);
    reconcile_if_chain_rolled_back(home, wallet, &*chain, &seed, &mut store, &log);
    let mut w = uv_app::wallet::Wallet { seed, store, log };

    // Pull anything new into the inbox first. From here down nothing knows or
    // cares how it arrived. A carrier that is down is not fatal: whatever is
    // already here is still worth processing.
    let carrier = make_transport(transport_kind, home, wallet);
    match carrier.take(&mailbox(home, "inbox")) {
        Ok(0) => {}
        Ok(n) => println!("fetched {n} new bundle(s) from {}", carrier.describe()),
        Err(e) => {
            println!("could not reach {}: {e}", carrier.describe());
            println!("  checking what is already here instead");
        }
    }

    let outcome = uv_app::commands::scan_inbox(home, wallet, &mut w, chain.as_ref(), &anchor)
        .unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        });

    use uv_app::commands::ScanEvent;
    for ev in &outcome.events {
        match ev {
            ScanEvent::SkippedOversize { file, bytes } => {
                println!("skipped {file}: {bytes} bytes, larger than any real payment")
            }
            ScanEvent::Accepted { amount, hops } => println!("accepted {amount} ({hops} hops)"),
            ScanEvent::SlotCollision {
                amount,
                slot,
                peer,
                set_aside,
                aside_dir,
            } => {
                println!("cannot accept {amount}: slot {slot} already holds a different note");
                match peer.as_deref() {
                    Some(who) => println!(
                        "  slot {slot} is from the batch handed to {who} — so that batch \
                         reached two payers."
                    ),
                    None => println!(
                        "  two payers used the same address slot. The payment is real \
                         and settled on Bitcoin; it simply has nowhere to sit."
                    ),
                }
                if *set_aside {
                    println!("  moved to {} — NOT lost.", aside_dir.display());
                    println!(
                        "  to collect it: send that payer a fresh address and ask them \
                         to re-mail against a slot you have not been paid at."
                    );
                } else {
                    println!("  could not set it aside; leaving it in the inbox.");
                }
            }
            ScanEvent::StoreRefused { amount, why } => {
                println!("cannot accept {amount}: {why} — keeping")
            }
            ScanEvent::RejectedPermanent { amount, why } => {
                println!("rejected {amount} ({why}) — discarded")
            }
            ScanEvent::RejectedTransient { amount, why } => {
                println!("rejected {amount} ({why}) — keeping, may settle later")
            }
        }
    }

    // Durable first, irreversible second: the accepted notes are only in
    // memory until this save; `finish()` deletes their files after it.
    save_wallet(home, wallet, &w.seed, &w.store, &w.log);
    let (a, r) = (outcome.accepted, outcome.rejected);
    outcome.finish();
    println!("accepted {a}, rejected {r}");
}

fn cmd_balance(home: &Path, wallet: &str) {
    // The sum and the classification live in `uv-app` (only Unspent counts —
    // the exhaustive-state test is there); this layer only formats.
    let (seed, store, log) = load_wallet(home, wallet);
    let b = uv_app::commands::balance(&uv_app::wallet::Wallet { seed, store, log });
    println!("{}", b.spendable);
    for line in &b.notes {
        println!(
            "  {:<12} {:>8}  {}",
            format!("{:?}", line.state),
            line.amount,
            line.commitment_hex
        );
    }
}

/// Everything needed to answer "why is my money not where I expect".
///
/// Referenced by two comments (`wallet2/src/chain.rs`, `btc/src/lib.rs`) for a
/// while before it existed. Written now because the moment two people run this
/// on two machines, "my balance is 0" has half a dozen causes — a chain view
/// that cannot see far enough, a note still too shallow, a reorg nobody
/// reconciled, mail that never arrived — and `balance` distinguishes none of
/// them because it never touches the chain.
///
/// Every chain question here degrades rather than aborts: a node that is down
/// should produce a report saying so, not no report at all.
fn cmd_status(home: &Path, backend: &str, wallet: &str) {
    // The probes and their degradations live in `uv-app` (`commands::status`);
    // this layer formats. A node that is down produces a report saying so.
    let (seed, store, log) = load_wallet(home, wallet);
    let w = uv_app::wallet::Wallet { seed, store, log };
    let chain = make_chain(backend, home);
    let s = uv_app::commands::status(home, wallet, &w, chain.as_ref());

    println!("wallet   {wallet}");
    println!("id       {}", s.address_id);
    println!("backend  {backend}");
    match &s.tip {
        Ok(t) => println!("tip      {t}"),
        Err(e) => println!("tip      UNAVAILABLE ({e})"),
    }
    println!(
        "view     from height {}{}",
        s.scan_floor,
        if s.scan_floor == 0 {
            " (covers the whole chain)"
        } else {
            " — CANNOT answer for anything below this"
        }
    );
    println!("rollbacks {}", s.rollback_epoch);

    match &s.anchor {
        uv_app::commands::AnchorLine::Present {
            asset_hex,
            issued_below,
        } => {
            println!("asset    {asset_hex}");
            match issued_below {
                Some(h) => println!("issued   below height {h}"),
                None => println!("issued   below UNKNOWN — an anchor written before floors"),
            }
        }
        uv_app::commands::AnchorLine::Absent => {
            println!("asset    no anchor.json — this wallet cannot validate anything")
        }
        uv_app::commands::AnchorLine::Unreadable(why) => {
            println!("asset    anchor.json UNREADABLE — {why}")
        }
    }

    let n = &s.notes;
    println!(
        "notes    {} unspent, {} in flight, {} spent, {} quarantined",
        n.unspent, n.in_flight, n.spent, n.quarantined
    );
    println!("spendable {}", n.spendable);

    for line in &s.in_flight {
        let verdict = match &line.verdict {
            uv_app::commands::InFlightVerdict::Confirmations { depth, need } => format!(
                "{depth} confirmation(s), needs {need}{}",
                if depth >= need { " — settled" } else { "" }
            ),
            uv_app::commands::InFlightVerdict::NoRecord => "no record on chain yet".into(),
            uv_app::commands::InFlightVerdict::Unanswerable => {
                "this chain view cannot say".to_string()
            }
            uv_app::commands::InFlightVerdict::LogMissingPayload => {
                "signed but the log has no payload — should be impossible".into()
            }
        };
        println!("  in flight {:>8}  {verdict}", line.amount);
    }

    if !s.batches.is_empty() {
        println!("addresses handed out:");
        for b in &s.batches {
            println!(
                "  slots {}..{}  to {}  — {} of {} paid so far",
                b.first,
                b.first + b.count,
                b.peer
                    .as_deref()
                    .unwrap_or("(unrecorded — use --for next time)"),
                b.used,
                b.count
            );
        }
    }

    if s.stuck > 0 {
        println!(
            "STUCK    {} payment(s) set aside in this home (not necessarily this wallet's)",
            s.stuck
        );
        println!("         {}", s.stuck_dir.display());
        println!("         Real, settled, and with no free slot to sit in. Whoever they were");
        println!("         for should send that payer a fresh address to re-mail against.");
    }
}

fn cmd_reconcile(home: &Path, backend: &str, wallet: &str) {
    let (seed, mut store, log) = load_wallet(home, wallet);
    let chain = make_chain(backend, home);
    let parts = genesis_parts(home);
    let genesis = parts.as_ref().map(|(a, c, amt)| Genesis {
        asset: a,
        commitment: c,
        amount: *amt,
    });
    let out = reconcile(&*chain, &mut store, &log, genesis.as_ref());
    save_wallet(home, wallet, &seed, &store, &log);
    // Restored first: a note coming back is the news a person is waiting on,
    // and this used to be silent — the pass released the note and said nothing.
    if !out.restored.is_empty() {
        println!(
            "{} note(s) RESTORED — their ancestry settles again:",
            out.restored.len()
        );
        for c in &out.restored {
            println!("  {}", hex::encode(c));
        }
    }
    if out.quarantined.is_empty() {
        println!("all held notes still settle");
    } else {
        println!("{} note(s) quarantined:", out.quarantined.len());
        for c in &out.quarantined {
            println!("  {}", hex::encode(c));
        }
    }
    if !out.unverifiable.is_empty() {
        // Said loudly, and not folded into the quarantine count: these notes
        // were not judged at all. The chain view could not see far enough back
        // to answer, so their state is untouched — a wallet that quarantined
        // on "I cannot tell" would freeze the user's money whenever their node
        // was mid-resync.
        println!(
            "{} note(s) COULD NOT BE CHECKED — the chain view does not reach far",
            out.unverifiable.len()
        );
        println!("  their state is unchanged; widen the view and reconcile again");
        for c in &out.unverifiable {
            println!("  {}", hex::encode(c));
        }
    }
}

#[cfg(test)]
mod reservation_key {
    // The derivation lives in `uv-app` (`slots::address_id`), the one place
    // both callers name reservation files from; the vector is pinned here at
    // the CLI so the end-to-end contract cannot move even if the app crate's
    // own tests are rewritten.
    fn address_id(x: &str, k: &str) -> String {
        uv_app::slots::address_id(x, k)
    }

    /// **A known vector, because the value must never change.**
    ///
    /// This names the file that records which of a payee's one-time slots a
    /// payer has already used. If the derivation ever moves, every existing
    /// reservation becomes invisible, the payer re-uses slot 0, and two notes
    /// end up under one WOTS+ key — which is key disclosure, arriving silently.
    ///
    /// It was `DefaultHasher`, whose output is explicitly not stable across
    /// Rust releases, while `rust-toolchain.toml` floats on `stable`. So a
    /// `rustup update` was enough to trigger it. A literal is the only thing
    /// that makes that a test failure instead of a quiet loss.
    #[test]
    fn the_reservation_filename_is_stable_forever() {
        assert_eq!(
            address_id("aa", "bb"),
            "539e6552b5ca09b3",
            "the reservation filename derivation changed. If that was \
             deliberate, understand first that every payer's existing \
             reservations become unreadable and slots will be re-used."
        );
    }

    /// The two fields are length-prefixed, so content cannot slide between
    /// them. Without that, ("ab","c") and ("a","bc") would be one address.
    #[test]
    fn the_two_key_halves_cannot_be_slid_into_one_another() {
        assert_ne!(address_id("ab", "c"), address_id("a", "bc"));
    }

    /// Different addresses get different files.
    #[test]
    fn different_addresses_get_different_files() {
        assert_ne!(address_id("aa", "bb"), address_id("aa", "bc"));
    }
}
