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
//! Issuance policy — who may mint an asset, how the anchor is published — is
//! spec/02+09 work.

mod vault;

use uv_cli::transport::{Directory, Relay, SignalCli, Transport};

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use uv_air::prove::{hiding_config, HidingConfig, Vouched};
use uv_air::wots::Digest;
use uv_btc::BitcoinChain;
use uv_kernel2::amount::Amount;
use uv_kernel2::digest;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_wallet2::accept::{accept, Lineage};
use uv_wallet2::chain::{Chain, FileChain};
use uv_wallet2::reconcile::reconcile;
use uv_wallet2::send::{broadcast, prepare, rebroadcast, Recipient, WalletCtx};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

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

#[derive(Serialize, Deserialize)]
struct WalletFile {
    seed_hex: String,
    store: Store,
    log: SignLog,
}

/// One payment slot: everything a payer needs to build a note for this payee,
/// and nothing that lets the payer spend it or watch it.
///
/// Per-slot by decision (spec/99 [ANCHOR-REUSE]): each slot's anchor is used once, so
/// no secret of the payee's outlives the spend it authorizes. The alternative —
/// one long-lived anchor anyone could pay — would put that secret in every
/// spend's witness, and is gated on the circuit review.
#[derive(Clone, Serialize, Deserialize)]
struct Slot {
    index: u64,
    owner_pk_hex: String,
    nullifier_anchor_hex: String,
    randomness_hex: String,
}

/// An address: a batch of unused slots, handed over once on first contact.
///
/// This is Signal's prekey pattern, and it is the honest shape of a
/// "non-interactive" address over hash-based keys. There is no per-payment
/// invoice — a payer takes the next unused slot and pays whenever it likes,
/// with the payee offline. What it does need is that first handover, and
/// replenishment before the batch runs out.
#[derive(Serialize, Deserialize)]
struct Address {
    /// Where to seal payments to. Hybrid ML-KEM-768 + X25519 — off the money
    /// path, so a lattice break costs privacy and never a coin.
    scan: uv_envelope::ScanPublic,
    slots: Vec<Slot>,
}

/// What travels to the payee: which request this pays, and the full lineage.
#[derive(Serialize, Deserialize)]
struct Bundle {
    index: u64,
    amount: u64,
    asset_hex: String,
    lineage: Lineage,
}

fn wallet_path(home: &Path, name: &str) -> PathBuf {
    home.join("wallets").join(format!("{name}.uvw"))
}
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

/// The filename key for an address's slot reservations.
///
/// Derived from the address's *contents* — the scan key identifies the
/// address and the slots hang off it — so copying `bob.json` to `bob2.json`
/// cannot reset the reservations, and two payees whose files share a name
/// cannot share a list.
///
/// **Must be stable forever.** If this value ever changes for an address a
/// payer has already used, the old reservations become invisible and the payer
/// re-uses slots — two notes under one one-time key. A hash whose stability is
/// a documented guarantee, not an implementation detail.
fn address_id(scan: &uv_envelope::ScanPublic) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    // Length-prefixed so the two fields cannot be slid into one another.
    for field in [&scan.x25519_hex, &scan.ml_kem_hex] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    hex::encode(&h.finalize()[..8])
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

/// Wallet file header: four magic bytes, then one byte saying whether the rest
/// is sealed.
///
/// Sealed and plaintext used to be told apart by *trying to parse* the file as
/// a vault and seeing whether it worked. That only functions while both formats
/// are JSON, and it silently misreads anything unexpected. A header says so
/// outright, and lets an old file be refused with an explanation instead of a
/// panic.
const WALLET_MAGIC: &[u8; 4] = b"UVW1";
const WALLET_PLAIN: u8 = 0;
const WALLET_SEALED: u8 = 1;

fn load_wallet(home: &Path, name: &str) -> (WalletSeed, Store, SignLog) {
    let p = wallet_path(home, name);
    if let Ok(bytes) = std::fs::read(&p) {
        if bytes.len() < 5 || &bytes[..4] != WALLET_MAGIC {
            eprintln!(
                "{}: not an Ultraviolet wallet file, or one written before the \n\
                 format changed from JSON to a binary encoding. A wallet holds every \n\
                 note's lineage, and lineages are mostly proof bytes: pretty-printed \n\
                 JSON turned a real wallet into tens of megabytes. There is no \n\
                 converter, because nothing here holds value yet — start a fresh \n\
                 wallet, or check out an earlier commit to read the old one.",
                p.display()
            );
            std::process::exit(1);
        }
        let body = &bytes[5..];
        let plain = match bytes[4] {
            WALLET_SEALED => {
                let v: vault::Vault = bincode::deserialize(body).unwrap_or_else(|_| {
                    eprintln!("wallet is marked sealed but its envelope is unreadable");
                    std::process::exit(1);
                });
                let pw = passphrase_for_open().unwrap_or_else(|| {
                    eprintln!("this wallet is encrypted; a passphrase is required");
                    std::process::exit(1);
                });
                vault::open(&pw, &v).unwrap_or_else(|_| {
                    eprintln!("cannot open wallet: wrong passphrase, or the file was altered");
                    std::process::exit(1);
                })
            }
            WALLET_PLAIN => body.to_vec(),
            other => {
                eprintln!("unknown wallet format marker {other}");
                std::process::exit(1);
            }
        };
        let wf: WalletFile = bincode::deserialize(&plain).expect("wallet file");
        if !wf.log.version_ok() {
            // Reading this as empty would remove the only thing standing
            // between a restored wallet and a second signature under one
            // one-time key. An older log was keyed by note commitment rather
            // than by derivation index, so it answers "has this key signed?"
            // wrongly while looking perfectly well-formed.
            eprintln!(
                "{}: the sign-log is an older format and cannot be trusted to \n\
                 answer whether a key has already signed. Reading it as empty \n\
                 would risk disclosing a one-time key. Start a fresh wallet, or \n\
                 check out an earlier commit to read this one.",
                p.display()
            );
            std::process::exit(1);
        }
        let sv = hex::decode(&wf.seed_hex).expect("seed hex");
        let seed: [u8; 32] = sv.as_slice().try_into().expect("32-byte seed");
        return (WalletSeed(seed), wf.store, wf.log);
    }
    // A fresh wallet. The seed is the only thing that must be backed up — plus
    // the sign log, which is not a cache (spec/02).
    let mut seed = [0u8; 32];
    getrandom(&mut seed);
    (WalletSeed(seed), Store::new(), SignLog::new())
}

/// 32 bytes of OS randomness, without pulling in a crate for it.
fn getrandom(buf: &mut [u8; 32]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .expect("urandom")
        .read_exact(buf)
        .expect("read urandom");
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
    let p = wallet_path(home, name);
    std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| format!("mkdir: {e}"))?;
    let wf = WalletFile {
        seed_hex: hex::encode(seed.0),
        store: clone_store(store),
        log: clone_log(log),
    };
    // bincode, not pretty JSON. A wallet stores every held note's full lineage,
    // and a lineage is mostly proof bytes — JSON wrote each one as its own
    // decimal number on its own line, which made the demo's largest wallet
    // 46 MB across 2.77 million lines. The encryption path was paying for it
    // too, since the bloated bytes were what got sealed.
    let plain = bincode::serialize(&wf).map_err(|e| format!("serialize wallet: {e}"))?;
    let mut bytes = Vec::with_capacity(plain.len() + 5);
    bytes.extend_from_slice(WALLET_MAGIC);
    match passphrase_for_save() {
        Some(pw) => {
            bytes.push(WALLET_SEALED);
            let sealed = bincode::serialize(&vault::seal(&pw, &plain))
                .map_err(|e| format!("seal wallet: {e}"))?;
            bytes.extend_from_slice(&sealed);
        }
        None => {
            bytes.push(WALLET_PLAIN);
            bytes.extend_from_slice(&plain);
        }
    }
    std::fs::write(&p, bytes).map_err(|e| format!("write wallet {}: {e}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// serde round-trip clones, so the persisted types need no Clone bound.
fn clone_store(s: &Store) -> Store {
    serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap()
}
fn clone_log(l: &SignLog) -> SignLog {
    serde_json::from_slice(&serde_json::to_vec(l).unwrap()).unwrap()
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

#[derive(Serialize, Deserialize)]
struct Anchor {
    asset_hex: String,
    commitment_hex: String,
    /// The chain height below which none of this asset's records can exist.
    ///
    /// A receiver whose chain view starts *above* this cannot rule out an
    /// earlier conflicting record, which is how an index with too high a floor
    /// makes a double-spend look valid. `Option`, not a defaulted `u64`: an
    /// anchor written before this existed must read as "unknown" and refuse a
    /// non-zero floor, not as "height 0" that quietly passes.
    ///
    /// Stamped at *tip minus a reorg margin*, never the bare tip — the tip at
    /// issue time can itself be reorged away, and a record could then land
    /// below the floor. Off by one reorg is a silent fail-open.
    #[serde(default)]
    issued_below: Option<u64>,
}

fn cmd_issue(home: &Path, backend: &str, wallet: &str, amount: u64) {
    let (seed, mut store, log) = load_wallet(home, wallet);
    let index = store.allocate_index();
    let keys = derive(&seed, index);
    // The asset id is the issuance note's own owner key: one asset per issuance,
    // deterministic, and unforgeable without the issuer's seed. (A richer
    // issuance policy — tickers, supply caps, reissuance — is spec/02+09.)
    let asset = keys.nullifier_key;
    let note = Note::build(asset, Amount(amount), &keys);
    let commitment = note.commitment();
    store
        .insert(Held {
            note,
            key_index: index,
            lineage: Lineage::new(),
            state: NoteState::Unspent,
        })
        .expect("fresh index");
    save_wallet(home, wallet, &seed, &store, &log);
    // Issuance publishes nothing, and every record of this asset's lineage is
    // published strictly after it — so the height at issue time is a sound
    // floor. Minus a margin, because that tip can itself be reorged away.
    let issued_below = {
        let chain = make_chain(backend, home);
        // Refuse rather than stamp a floor from a failed call: an anchor's
        // floor is permanent, and `None` here would silently weaken the asset
        // forever. The issuance can simply be retried when the node is back.
        let tip = chain.tip().unwrap_or_else(|e| {
            eprintln!("cannot stamp the issuance floor: {e}");
            eprintln!("no note was created; retry when the node answers");
            std::process::exit(1);
        });
        Some(tip.saturating_sub(REORG_MARGIN))
    };
    let anchor = Anchor {
        asset_hex: hexd(&asset),
        commitment_hex: hexd(&commitment),
        issued_below,
    };
    std::fs::write(
        anchor_path(home),
        serde_json::to_vec_pretty(&anchor).unwrap(),
    )
    .expect("write anchor");
    println!("issued {amount} to {wallet}");
    println!("asset      {}", anchor.asset_hex);
    println!("anchor     {}", anchor.commitment_hex);
    println!("(receivers validate every lineage against this anchor)");
}

/// One batch of slots, and who it was handed to.
///
/// A sidecar rather than a field in the wallet: the wallet is read with plain
/// `bincode`, which is not self-describing, so a new field there would panic on
/// every wallet that already exists.
#[derive(Serialize, Deserialize)]
struct Batch {
    /// Free-text label for the counterparty. Not an identity — nothing
    /// authenticates it — just what the payee called them when handing it over.
    peer: Option<String>,
    first: u64,
    count: u64,
}

fn batches_path(home: &Path, wallet: &str) -> PathBuf {
    home.join(format!("batches-{wallet}.json"))
}

fn read_batches(home: &Path, wallet: &str) -> Vec<Batch> {
    std::fs::read(batches_path(home, wallet))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Which batch an index came from, if any — so a collision can name the peer
/// whose batch was double-handed rather than only the slot number.
fn batch_of(batches: &[Batch], index: u64) -> Option<&Batch> {
    batches
        .iter()
        .find(|b| index >= b.first && index < b.first + b.count)
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
    let bytes = std::fs::read(from).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", from.display());
        std::process::exit(1);
    });
    let incoming: Anchor = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        eprintln!("not an anchor file: {e}");
        std::process::exit(1);
    });
    if try_unhexd(&incoming.asset_hex).is_none() || try_unhexd(&incoming.commitment_hex).is_none() {
        eprintln!("anchor fields are not canonical digests; refusing");
        std::process::exit(1);
    }

    // Refuse to silently replace a *different* asset. A home holds one anchor,
    // so overwriting it orphans every note of the old asset — they stay in the
    // wallet and stop validating, with nothing said. A second `uv issue` does
    // this too; this is the path that at least asks.
    if let Some(existing) = std::fs::read(anchor_path(home))
        .ok()
        .and_then(|b| serde_json::from_slice::<Anchor>(&b).ok())
    {
        if existing.asset_hex != incoming.asset_hex {
            eprintln!("this home already holds a different asset:");
            eprintln!("  have {}", existing.asset_hex);
            eprintln!("  new  {}", incoming.asset_hex);
            eprintln!("Importing would orphan every note of the one you have — they would stay");
            eprintln!("in the wallet and quietly stop validating. Use a separate --home.");
            std::process::exit(1);
        }
        if existing.issued_below != incoming.issued_below {
            // The floor is a security parameter: a *higher* one hides records
            // below it, which is how a double-spend passes. Keep the lower.
            let keep = match (existing.issued_below, incoming.issued_below) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            };
            eprintln!(
                "note: issuance floors differ ({:?} vs {:?}); keeping the safer {:?}",
                existing.issued_below, incoming.issued_below, keep
            );
            let merged = Anchor {
                asset_hex: incoming.asset_hex.clone(),
                commitment_hex: incoming.commitment_hex.clone(),
                issued_below: keep,
            };
            std::fs::write(
                anchor_path(home),
                serde_json::to_vec_pretty(&merged).unwrap(),
            )
            .expect("write anchor");
            println!("anchor updated (floor merged downward)");
            return;
        }
    }
    std::fs::write(anchor_path(home), &bytes).expect("write anchor");
    println!("anchor installed: asset {}", incoming.asset_hex);
    match incoming.issued_below {
        Some(h) => println!("this asset has no records below height {h}"),
        None => println!("no issuance floor recorded — a narrow chain view cannot be checked"),
    }
}

fn cmd_address(home: &Path, wallet: &str, count: u64, out: Option<PathBuf>, peer: Option<&str>) {
    let (seed, mut store, log) = load_wallet(home, wallet);
    let perm = uv_air::wots::permutation();
    let slots: Vec<Slot> = (0..count)
        .map(|_| {
            let index = store.allocate_index();
            let keys = derive(&seed, index);
            Slot {
                index,
                owner_pk_hex: hexd(&uv_air::wots::public_key(&perm, &keys.wots_seed)),
                nullifier_anchor_hex: hexd(&keys.anchor),
                randomness_hex: hexd(&keys.randomness),
            }
        })
        .collect();
    save_wallet(home, wallet, &seed, &store, &log);

    // Record the batch before handing it out, so the ledger can never claim
    // fewer slots are outstanding than really are.
    if let Some(first) = slots.first().map(|s| s.index) {
        let mut batches = read_batches(home, wallet);
        batches.push(Batch {
            peer: peer.map(str::to_string),
            first,
            count,
        });
        let _ = std::fs::write(
            batches_path(home, wallet),
            serde_json::to_vec_pretty(&batches).unwrap(),
        );
    }

    let (_, scan) = uv_envelope::derive_scan(&seed.0);
    let json = serde_json::to_vec_pretty(&Address { scan, slots }).unwrap();
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
    let address: Address =
        serde_json::from_slice(&std::fs::read(to).expect("read address")).expect("address json");
    // Keyed on the address's *contents*, not its filename. Keyed on the file
    // stem, copying `bob.json` to `bob2.json` reset every reservation, and two
    // unrelated payees whose files happened to share a stem shared one list.
    // The scan key identifies the address; the slots hang off it.
    //
    // SHA-256, not `DefaultHasher`. `DefaultHasher`'s output is explicitly not
    // stable across Rust releases, and `rust-toolchain.toml` floats on
    // `stable` — so a routine `rustup update` would rename every
    // `used-slots-*.json`, every slot would read as unused, and two notes
    // would end up under one WOTS+ one-time key. That is key disclosure
    // triggered by a toolchain bump, with nothing to see. Pinned by
    // `the_reservation_filename_is_stable_forever`.
    let addr_id = address_id(&address.scan);
    let used_path = home.join(format!("used-slots-{addr_id}.json"));
    // Absent means "nothing reserved yet". Unreadable means the file that
    // stops a slot being used twice is broken, and a slot used twice hands two
    // notes the same one-time key. This used to collapse both into an empty
    // list — and since the file is written with `.expect(...)`, a partial write
    // on a full disk produced exactly the input that then parsed to `[]`.
    let mut used: Vec<u64> = match std::fs::read(&used_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!("cannot read {}: {e}", used_path.display());
            eprintln!(
                "this file records which address slots are already spent; \
                       continuing could reuse one and disclose a signing key"
            );
            std::process::exit(1);
        }
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!("{} is corrupt: {e}", used_path.display());
            eprintln!("refusing rather than treating every slot as unused");
            std::process::exit(1);
        }),
    };

    let (seed, mut store, mut log) = load_wallet(home, wallet);
    let mut chain = make_chain(backend, home);
    let cfg = prover_config();
    // Spending a note whose ancestry was just orphaned is the loss case, so
    // this matters here at least as much as in `scan`.
    reconcile_if_chain_rolled_back(home, wallet, &*chain, &seed, &mut store, &log);
    let anchor: Anchor = match std::fs::read(anchor_path(home)) {
        Ok(b) => serde_json::from_slice(&b).expect("anchor json"),
        Err(_) => {
            eprintln!("no anchor.json — nothing to pay with");
            std::process::exit(1);
        }
    };
    let asset: Digest = unhexd(&anchor.asset_hex);

    // Which notes fund this. A transfer takes exactly one input, so a payment
    // larger than any single note becomes several payments that add up
    // (spec/99 [MERGE]). Selection happens once, here, against the store as it
    // is now — never inside the loop, where iteration two could pick the change
    // note iteration one just created, whose lineage ends in a one-block-deep
    // hop the payee would bounce.
    let plan: Vec<(Digest, Amount)> = match from {
        Some(hexs) => vec![(unhexd(hexs), Amount(amount))],
        None => uv_wallet2::store::select(&store, &asset, Amount(amount)).unwrap_or_else(|| {
            let have: u64 = store
                .iter()
                .filter(|h| h.state == NoteState::Unspent && h.note.asset == asset)
                .map(|h| h.note.amount.0)
                .sum();
            let other: u64 = store
                .iter()
                .filter(|h| h.state == NoteState::Unspent && h.note.asset != asset)
                .map(|h| h.note.amount.0)
                .sum();
            eprintln!("spendable balance is {have} for this asset, cannot pay {amount}");
            if other > 0 {
                // Worth saying out loud: a wallet can look full and still be
                // unable to pay, because notes of another asset cannot fund
                // this one. `anchor.json` names the asset a payment is for.
                eprintln!("({other} held in notes of a different asset, which cannot fund this)");
            }
            std::process::exit(1);
        }),
    };

    // A note whose key already signed is a *rebroadcast*, not a new payment:
    // the replayed payload pays whoever the original one paid, so it needs no
    // slot and mails nothing. Sorting that out here, before any reservation, is
    // what stops a replay burning a fresh slot on a bundle the payee is
    // guaranteed to refuse as `NotAnOutput`.
    let replays: Vec<Digest> = plan
        .iter()
        .filter(|(c, _)| store.get(c).is_some_and(|h| log.get(h.key_index).is_some()))
        .map(|(c, _)| *c)
        .collect();
    let fresh: Vec<(Digest, Amount)> = plan
        .iter()
        .filter(|(c, _)| !replays.contains(c))
        .cloned()
        .collect();

    // Everything that can refuse, refuses now — before a single record reaches
    // Bitcoin. A payment that publishes two of its three records and then hits
    // an exhausted address has spent real money and paid nobody in full.
    let free: Vec<&Slot> = address
        .slots
        .iter()
        .filter(|s| !used.contains(&s.index))
        .collect();
    if free.len() < fresh.len() {
        let (n, s_note) = (fresh.len(), if fresh.len() == 1 { "" } else { "s" });
        let (f, s_slot) = (free.len(), if free.len() == 1 { "" } else { "s" });
        if f == 0 {
            eprintln!("address exhausted: every slot is spent, ask for a fresh batch");
        } else {
            eprintln!(
                "this payment needs {n} note{s_note} and the address has {f} slot{s_slot} \
                 left — ask for a fresh batch"
            );
        }
        std::process::exit(1);
    }

    // Validate every slot we are about to reserve, before reserving any. A
    // malformed hex field used to panic *after* the reservation write, so one
    // bad slot in the middle of a multi-note plan burnt every slot in it.
    let slots: Vec<Slot> = free.into_iter().take(fresh.len()).cloned().collect();
    for sl in &slots {
        for (what, hexs) in [
            ("owner_pk", &sl.owner_pk_hex),
            ("nullifier_anchor", &sl.nullifier_anchor_hex),
            ("randomness", &sl.randomness_hex),
        ] {
            if try_unhexd(hexs).is_none() {
                eprintln!("address slot {}: {what} is not a valid digest", sl.index);
                eprintln!("refusing before reserving anything");
                std::process::exit(1);
            }
        }
    }
    // And the scan key — the one field the slot loop above does not cover,
    // which was found the hard way: sealing the bundle `.expect()`ed on it
    // *after* the record was on Bitcoin, so a malformed scan key cost the
    // payment and the slot and mailed nothing. Probe it with a real seal of an
    // empty payload rather than re-implementing the hex/length rules here:
    // validation by the exact function later trusted cannot drift from it.
    if !fresh.is_empty() && uv_envelope::seal(&address.scan, &[]).is_err() {
        eprintln!("address scan key is malformed: bundles could never be sealed to this payee");
        eprintln!("refusing before reserving anything");
        std::process::exit(1);
    }

    // Reserve the slots *before* publishing anything.
    //
    // This ordering is not tidiness. Slot reservations used to be written after
    // the mailing, so a crash mid-payment lost them, a retry reused slot 0, and
    // two notes built on one slot share a one-time signing key. Sign both and
    // the key is disclosed. Reserving first costs, at worst, a slot burnt by a
    // payment that never happened.
    if !slots.is_empty() {
        for sl in &slots {
            used.push(sl.index);
        }
        std::fs::write(&used_path, serde_json::to_vec(&used).unwrap()).expect("reserve slots");
    }

    if plan.len() > 1 {
        let parts: Vec<String> = plan.iter().map(|(_, v)| v.0.to_string()).collect();
        println!(
            "no single note covers {amount}; paying as {} notes ({})",
            plan.len(),
            parts.join(" + ")
        );
    }

    let carrier = make_transport(transport_kind, home, wallet);
    let mut published = 0usize;

    // Rebroadcasts first, and separately, because they are not this payment.
    // Each one re-publishes bytes some earlier command already signed, paying
    // whoever that command paid. Nothing here is mailed and no slot is spent:
    // the payee was mailed a bundle the first time round, and one naming a
    // fresh slot would describe an output the transfer does not create.
    for input in &replays {
        let key_index = store.get(input).expect("selected from the store").key_index;
        let sent = rebroadcast(&mut *chain, &log, key_index)
            .unwrap_or_else(|e| {
                eprintln!("could not rebroadcast: {e:?}");
                std::process::exit(1);
            })
            .expect("partitioned as a replay, so the log holds it");
        println!(
            "note {} was already spent — REBROADCAST its original signed payload",
            &hexd(input)[..16]
        );
        println!("  nf {}", hexd(&sent.transfer.nullifier));
        println!("  no new signature, no new proof, no slot spent, nothing mailed");
        println!("  it pays whoever the original payment paid, who already has the bundle");
    }
    if !replays.is_empty() && fresh.is_empty() {
        println!("nothing new to send: every selected note had already been spent");
        return;
    }

    for ((input, part), req) in fresh.iter().zip(slots.iter()) {
        let recipient = Recipient {
            owner_pk: unhexd(&req.owner_pk_hex),
            nullifier_anchor: unhexd(&req.nullifier_anchor_hex),
            randomness: unhexd(&req.randomness_hex),
        };
        // Sign and log, but do not broadcast — `prepare` takes no chain and
        // cannot. The wallet is persisted between here and the broadcast
        // below, which is the ordering the split exists to make unskippable:
        // a signature that reaches Bitcoin before it reaches disk is a
        // signature a crashed wallet will make again with a different slot,
        // and that discloses the one-time key.
        let prepared = prepare(
            &cfg,
            WalletCtx {
                store: &mut store,
                log: &mut log,
                seed: &seed,
            },
            input,
            &recipient,
            *part,
        )
        .unwrap_or_else(|e| {
            eprintln!("send refused: {e:?}");
            eprintln!("{published} of {} records already published", fresh.len());
            save_wallet(home, wallet, &seed, &store, &log);
            std::process::exit(1);
        });
        // The wallet write is handed to `broadcast` rather than done before
        // it. Same order as before; the difference is that the order is now
        // the only one expressible — see `send::broadcast`.
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
        let bundle = Bundle {
            index: req.index,
            amount: part.0,
            asset_hex: hexd(&asset),
            lineage,
        };
        let name = format!(
            "{}.uvb",
            hex::encode(digest::encode(&sent.transfer.nullifier))
        );
        // bincode, not JSON: the bundle is mostly proof bytes, and JSON encodes
        // a byte array as decimal numbers — ~4x bloat on the protocol's worst
        // scaling axis (one proof per hop of history).
        let plain = bincode::serialize(&bundle).unwrap();
        // The scan key was probe-sealed before anything was reserved, so this
        // cannot fail on a malformed key — but the record is already on
        // Bitcoin here, which is exactly where an abort costs the most, so a
        // failure still gets a diagnosis instead of a panic. The signed spend
        // is durable; the payee can be re-mailed, the money is not lost.
        let sealed = uv_envelope::seal(&address.scan, &plain).unwrap_or_else(|e| {
            eprintln!("could not seal the bundle to the payee: {e:?}");
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
        // bundle costs delivery and not money: the payment settled, the payee
        // simply has not been told. Say that rather than exiting on a payment
        // the wallet has already committed to.
        let wire = bincode::serialize(&sealed).expect("serialize sealed");
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

    if fresh.len() > 1 {
        println!(
            "paid {amount} as {} notes; {published} records published, {} slots consumed",
            fresh.len(),
            slots.len()
        );
    }
}

/// How far below the tip an issuance floor is stamped.
///
/// Must be at least as deep as any reorg the backend is willing to undo, or the
/// floor can end up *above* a record that later reorganises into existence
/// beneath it — and the floor would then hide it. Derived from the index's own
/// window rather than restated: these were two independent `144`s in two
/// crates, each documented as "a day of blocks", with nothing making them agree.
const REORG_MARGIN: u64 = uv_btc::index::REORG_WINDOW as u64;

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
    let out = reconcile(chain, store, log);
    if !out.quarantined.is_empty() {
        println!("{} note(s) quarantined:", out.quarantined.len());
        for c in &out.quarantined {
            println!("  {}", hex::encode(c));
        }
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
    let anchor: Anchor = match std::fs::read(anchor_path(home)) {
        Ok(b) => serde_json::from_slice(&b).expect("anchor json"),
        Err(_) => {
            eprintln!("no anchor.json — nothing to validate against");
            std::process::exit(1);
        }
    };
    let (seed, mut store, log) = load_wallet(home, wallet);
    let (scan_secret, _) = uv_envelope::derive_scan(&seed.0);
    let chain = make_chain(backend, home);
    reconcile_if_chain_rolled_back(home, wallet, &*chain, &seed, &mut store, &log);
    let cfg = prover_config();
    let asset = unhexd(&anchor.asset_hex);
    let anchor_commitment = unhexd(&anchor.commitment_hex);

    let dir = mailbox(home, "inbox");

    // Pull anything new into the inbox first. From here down nothing knows or
    // cares how it arrived — the accept/keep/discard/set-aside logic below is
    // the same code that has always run against this directory, which is what
    // makes a network carrier a small change rather than a rewrite.
    //
    // A carrier that is down is not fatal: whatever is already here is still
    // worth processing, and a scan that refused to look at settled mail because
    // a relay was unreachable would be worse than useless.
    let carrier = make_transport(transport_kind, home, wallet);
    match carrier.take(&dir) {
        Ok(0) => {}
        Ok(n) => println!("fetched {n} new bundle(s) from {}", carrier.describe()),
        Err(e) => {
            println!("could not reach {}: {e}", carrier.describe());
            println!("  checking what is already here instead");
        }
    }

    // Loaded so a collision can name the counterparty whose batch was handed
    // to two payers, which is the only actionable part of that message.
    let batches = read_batches(home, wallet);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    // Files to delete *after* the wallet is durable, never before.
    //
    // This is the receive-side half of the rule the send path enforces
    // structurally (`send::broadcast` takes its persist step as a parameter):
    // **the irreversible act must not precede the durable one.** It used to:
    // an accepted bundle was `remove_file`d inside the loop while its note
    // lived only in memory until `save_wallet` at the end. Any early exit in
    // between — and a slot collision was one, see below — deleted money that
    // had never been written down. Measured: a wallet owed 700 ended with 300.
    //
    // Deleting after the save is safe in the other direction too: a crash
    // between the two leaves a file whose note is already held, and the
    // duplicate check below skips it.
    let mut accepted_files: Vec<PathBuf> = Vec::new();
    // A bundle is one sealed envelope per hop of lineage, and `MAX_LINEAGE`
    // caps the hops, so anything past this ceiling is not a payment. Checked
    // against the directory entry's metadata *before* reading, because the
    // file is a stranger's and `read` would otherwise pull all of it into
    // memory before anything got a chance to object.
    const MAX_BUNDLE_BYTES: u64 = (uv_wallet2::accept::MAX_LINEAGE as u64 + 2) * 256 * 1024;

    let entries = std::fs::read_dir(&dir).into_iter().flatten().flatten();
    for e in entries {
        match e.metadata() {
            Ok(m) if m.len() > MAX_BUNDLE_BYTES => {
                println!(
                    "skipped {}: {} bytes, larger than any real payment",
                    e.file_name().to_string_lossy(),
                    m.len()
                );
                continue;
            }
            Ok(_) => {}
            Err(_) => continue,
        }
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        // Trial-decapsulation: an envelope that will not open was not for us.
        // There is no identifier to match on, by design — an identifier is
        // exactly the metadata this is meant not to leak.
        let Ok(sealed) = bincode::deserialize::<uv_envelope::Sealed>(&bytes) else {
            continue;
        };
        let Ok(plain) = uv_envelope::open(&scan_secret, &sealed) else {
            continue;
        };
        let Ok(bundle) = bincode::deserialize::<Bundle>(&plain) else {
            continue;
        };
        // Reconstruct the note from our own derivation — the sender never
        // sends us secrets, only which request they paid.
        let keys = derive(&seed, bundle.index);
        let note = Note::build(asset, Amount(bundle.amount), &keys);
        if store.get(&note.commitment()).is_some() {
            continue; // already ingested
        }
        match accept(
            &cfg,
            &*chain,
            &asset,
            &anchor_commitment,
            &note,
            &bundle.lineage,
            anchor.issued_below,
        ) {
            Ok(()) => {
                let hops = bundle.lineage.len();
                let held = Held {
                    note,
                    key_index: bundle.index,
                    lineage: bundle.lineage,
                    state: NoteState::Unspent,
                };
                match store.insert(held) {
                    Ok(()) => {
                        println!("accepted {} ({hops} hops)", bundle.amount);
                        accepted += 1;
                        accepted_files.push(e.path());
                    }
                    // **Never a panic.** `key_index` comes straight off the
                    // wire from whoever paid, and two payers holding the same
                    // address both start at slot zero without either doing
                    // anything wrong — `Store::insert`'s own doc comment says
                    // so. This used to `.expect()`, which aborted the scan
                    // mid-loop after earlier bundles had already been deleted.
                    //
                    // The payment is real and its record is on Bitcoin; what
                    // is missing is a free slot to hold it under. So the
                    // bundle is KEPT, not discarded: a fresh address makes it
                    // acceptable, and throwing it away would destroy the only
                    // copy of the lineage.
                    Err(uv_wallet2::store::StoreError::IndexReused(i)) => {
                        // Neither "accept" nor "discard" is right here, which
                        // is why it gets a third destination.
                        //
                        // It can never become acceptable: slot `i` is taken
                        // for good, so leaving it in the inbox would re-verify
                        // a whole lineage on every future scan — the
                        // amplification spec/99 [DOS-ORDER] already fixed for
                        // junk. But discarding it destroys the only copy of a
                        // real settled payment's lineage. So: set it aside,
                        // out of the scan path, where a human can find it.
                        let aside = mailbox(home, "unplaceable");
                        let moved = std::fs::create_dir_all(&aside).is_ok()
                            && e.file_name()
                                .to_str()
                                .map(|n| std::fs::rename(e.path(), aside.join(n)).is_ok())
                                .unwrap_or(false);
                        println!(
                            "cannot accept {}: slot {i} already holds a different note",
                            bundle.amount
                        );
                        match batch_of(&batches, i).and_then(|b| b.peer.as_deref()) {
                            Some(who) => println!(
                                "  slot {i} is from the batch handed to {who} — so that batch \
                                 reached two payers."
                            ),
                            None => println!(
                                "  two payers used the same address slot. The payment is real \
                                 and settled on Bitcoin; it simply has nowhere to sit."
                            ),
                        }
                        if moved {
                            println!("  moved to {} — NOT lost.", aside.display());
                            println!(
                                "  to collect it: send that payer a fresh address and ask them \
                                 to re-mail against a slot you have not been paid at."
                            );
                        } else {
                            println!("  could not set it aside; leaving it in the inbox.");
                        }
                        rejected += 1;
                    }
                    Err(other) => {
                        println!("cannot accept {}: {other:?} — keeping", bundle.amount);
                        rejected += 1;
                    }
                }
            }
            Err(why) => {
                // Junk mail used to live forever: rejected files were left in
                // place and re-verified on every subsequent scan, so one
                // bundle a stranger dropped in cost a proof verification per
                // hop, per scan, indefinitely. Throw away what can never
                // become valid; keep what is merely early.
                if why.is_permanent() {
                    println!("rejected {} ({why:?}) — discarded", bundle.amount);
                    let _ = std::fs::remove_file(e.path());
                } else {
                    println!(
                        "rejected {} ({why:?}) — keeping, may settle later",
                        bundle.amount
                    );
                }
                rejected += 1;
            }
        }
    }
    // Durable first, irreversible second. Everything accepted above is in the
    // store but only in memory until this line; the bundles that produced it
    // are still on disk, so a crash here costs a rescan and nothing else.
    save_wallet(home, wallet, &seed, &store, &log);
    for p in accepted_files {
        let _ = std::fs::remove_file(p);
    }
    println!("accepted {accepted}, rejected {rejected}");
}

fn cmd_balance(home: &Path, wallet: &str) {
    let (_, store, _) = load_wallet(home, wallet);
    let mut spendable = 0u64;
    for h in store.iter() {
        if h.state == NoteState::Unspent {
            spendable += h.note.amount.0;
        }
    }
    println!("{spendable}");
    for h in store.iter() {
        println!(
            "  {:<12} {:>8}  {}",
            format!("{:?}", h.state),
            h.note.amount.0,
            hexd(&h.note.commitment())
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
    let (_seed, store, log) = load_wallet(home, wallet);
    let chain = make_chain(backend, home);

    // The wallet's own scan-key fingerprint. Two people confirming they hold
    // the same address can read this to each other; it is the same value the
    // payer's reservation file is named after.
    let (_, own_scan) = uv_envelope::derive_scan(&_seed.0);
    println!("wallet   {wallet}");
    println!("id       {}", address_id(&own_scan));
    println!("backend  {backend}");
    match chain.tip() {
        Ok(t) => println!("tip      {t}"),
        Err(e) => println!("tip      UNAVAILABLE ({e})"),
    }
    let floor = chain.scan_floor();
    println!(
        "view     from height {floor}{}",
        if floor == 0 {
            " (covers the whole chain)"
        } else {
            " — CANNOT answer for anything below this"
        }
    );
    println!("rollbacks {}", chain.rollback_epoch());

    match std::fs::read(anchor_path(home))
        .ok()
        .and_then(|b| serde_json::from_slice::<Anchor>(&b).ok())
    {
        Some(a) => {
            println!("asset    {}", a.asset_hex);
            match a.issued_below {
                Some(h) => println!("issued   below height {h}"),
                None => println!("issued   below UNKNOWN — an anchor written before floors"),
            }
        }
        None => println!("asset    no anchor.json — this wallet cannot validate anything"),
    }

    let (mut unspent, mut inflight, mut spent, mut quarantined) = (0u64, 0u64, 0u64, 0u64);
    let mut spendable = 0u64;
    for h in store.iter() {
        match h.state {
            NoteState::Unspent => {
                unspent += 1;
                spendable += h.note.amount.0;
            }
            NoteState::InFlight => inflight += 1,
            NoteState::Spent => spent += 1,
            NoteState::Quarantined => quarantined += 1,
        }
    }
    println!("notes    {unspent} unspent, {inflight} in flight, {spent} spent, {quarantined} quarantined");
    println!("spendable {spendable}");

    // In-flight notes are the ones a person is usually waiting on, so say
    // exactly what the chain thinks of each rather than making them guess.
    for h in store.iter().filter(|h| h.state == NoteState::InFlight) {
        let nf = log.get(h.key_index).map(|s| s.transfer.nullifier);
        let verdict = match nf {
            Some(nf) => match chain.first_occurrence(&nf) {
                uv_wallet2::chain::Lookup::Found(o) => {
                    let need = uv_wallet2::chain::required_confirmations(h.note.amount.0);
                    format!(
                        "{} confirmation(s), needs {need}{}",
                        o.depth,
                        if o.depth >= need { " — settled" } else { "" }
                    )
                }
                uv_wallet2::chain::Lookup::None => "no record on chain yet".into(),
                uv_wallet2::chain::Lookup::Unanswerable => "this chain view cannot say".to_string(),
            },
            None => "signed but the log has no payload — should be impossible".into(),
        };
        println!("  in flight {:>8}  {verdict}", h.note.amount.0);
    }

    // Which slot batches are outstanding, so replenishment is answerable
    // rather than guesswork. The payee cannot see which slots a payer has
    // consumed — that state is payer-local by design — so this reports what
    // was handed out, not what is left.
    let batches = read_batches(home, wallet);
    if !batches.is_empty() {
        println!("addresses handed out:");
        for b in &batches {
            let used = store
                .iter()
                .filter(|h| h.key_index >= b.first && h.key_index < b.first + b.count)
                .count();
            println!(
                "  slots {}..{}  to {}  — {used} of {} paid so far",
                b.first,
                b.first + b.count,
                b.peer
                    .as_deref()
                    .unwrap_or("(unrecorded — use --for next time)"),
                b.count
            );
        }
    }

    // Mail nobody could place. Silent otherwise, so it only appears when it
    // matters — but when it matters it is the whole explanation.
    let aside = mailbox(home, "unplaceable");
    let stuck = std::fs::read_dir(&aside)
        .into_iter()
        .flatten()
        .flatten()
        .count();
    if stuck > 0 {
        // Reported per *home*, not per wallet, and said that way: the drop box
        // is one shared directory today, so this cannot tell whose payment it
        // is without trial-decapsulating on every wallet's behalf. It becomes
        // exact once delivery is per-recipient.
        println!(
            "STUCK    {stuck} payment(s) set aside in this home (not necessarily this wallet's)"
        );
        println!("         {}", aside.display());
        println!("         Real, settled, and with no free slot to sit in. Whoever they were");
        println!("         for should send that payer a fresh address to re-mail against.");
    }
}

fn cmd_reconcile(home: &Path, backend: &str, wallet: &str) {
    let (seed, mut store, log) = load_wallet(home, wallet);
    let chain = make_chain(backend, home);
    let out = reconcile(&*chain, &mut store, &log);
    save_wallet(home, wallet, &seed, &store, &log);
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
    use super::address_id;
    use uv_envelope::ScanPublic;

    fn scan(x: &str, k: &str) -> ScanPublic {
        ScanPublic {
            x25519_hex: x.into(),
            ml_kem_hex: k.into(),
        }
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
            address_id(&scan("aa", "bb")),
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
        assert_ne!(address_id(&scan("ab", "c")), address_id(&scan("a", "bc")));
    }

    /// Different addresses get different files; the same address gets the same
    /// one however it reached us.
    #[test]
    fn it_keys_on_contents_not_on_where_the_file_came_from() {
        assert_eq!(address_id(&scan("aa", "bb")), address_id(&scan("aa", "bb")));
        assert_ne!(address_id(&scan("aa", "bb")), address_id(&scan("aa", "bc")));
    }
}
