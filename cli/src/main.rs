//! `uv` — the Ultraviolet CLI wallet (POC).
//!
//! Ties the three nouns together against pluggable backends. Stage A wires the
//! file-backed mock chain + filesystem transport, so a full Alice→Bob→Carol
//! payment loop runs locally with no network. `--backend` will select regtest
//! / signet in later stages.
//!
//!   uv --home DIR address --wallet alice
//!   uv --home DIR issue   --wallet alice --amount 1000
//!   uv --home DIR send    --wallet alice --to <addr> --amount 300
//!   uv --home DIR scan    --wallet bob
//!   uv --home DIR balance --wallet bob

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use ultraviolet_kernel::hash::{boundary_hash, Hash256};
use ultraviolet_kernel::note::Note;
use ultraviolet_kernel::nullifier::{bundle_hash, Nullifier, Record};
use ultraviolet_kernel::transfer::{validate_transition, SpendInput, Transfer};
use uv_prove::{ProvedHop, Prover};
use uv_wallet::bundle::Bundle;
use uv_wallet::chain::{Chain, FileChain};
use uv_wallet::keys::{parse_address, scan_tag_for, Identity};
use uv_wallet::note::{NoteStore, OwnedNote};
use uv_wallet::transport::{FileTransport, Transport};

const TICKER: &str = "UVD";

#[derive(Parser)]
#[command(name = "uv", about = "Ultraviolet CLI wallet (POC)")]
struct Cli {
    /// Shared data directory (wallets, the mock chain, the mailbox).
    #[arg(long, global = true, default_value = "./uv-poc-data")]
    home: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a wallet's shareable address (creating the wallet if new).
    Address {
        #[arg(long)]
        wallet: String,
    },
    /// Issue (mint) a fungible asset into a wallet — a genesis hop.
    Issue {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        amount: u64,
    },
    /// Send an amount to an address.
    Send {
        #[arg(long)]
        wallet: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        /// Spend a note even if already marked spent — to demonstrate that the
        /// chain's first-occurrence rule rejects the double-spend downstream.
        #[arg(long, default_value_t = false)]
        allow_respend: bool,
    },
    /// Scan for incoming payments, verify them, and ingest the notes.
    Scan {
        #[arg(long)]
        wallet: String,
    },
    /// Print a wallet's spendable balance.
    Balance {
        #[arg(long)]
        wallet: String,
    },
}

/// Persisted wallet: the master seed plus the note store.
#[derive(Serialize, Deserialize)]
struct WalletFile {
    seed_hex: String,
    store: NoteStore,
}

fn wallets_dir(home: &Path) -> PathBuf {
    home.join("wallets")
}
fn wallet_path(home: &Path, name: &str) -> PathBuf {
    wallets_dir(home).join(format!("{name}.json"))
}
fn chain_path(home: &Path) -> PathBuf {
    home.join("chain.json")
}
fn mailbox_dir(home: &Path) -> PathBuf {
    home.join("mailbox")
}

fn load_or_create_wallet(home: &Path, name: &str) -> (Identity, NoteStore) {
    let path = wallet_path(home, name);
    if let Ok(bytes) = std::fs::read(&path) {
        let wf: WalletFile = serde_json::from_slice(&bytes).expect("parse wallet");
        let seed: [u8; 32] = hex::decode(&wf.seed_hex).unwrap().try_into().unwrap();
        (Identity::from_seed(seed), wf.store)
    } else {
        let seed: [u8; 32] = rand::random();
        (Identity::from_seed(seed), NoteStore::new())
    }
}

fn save_wallet(home: &Path, name: &str, id: &Identity, store: &NoteStore) {
    let dir = wallets_dir(home);
    std::fs::create_dir_all(&dir).expect("create wallets dir");
    let wf = WalletFile { seed_hex: hex::encode(id.master_seed()), store: store.clone() };
    std::fs::write(wallet_path(home, name), serde_json::to_vec_pretty(&wf).unwrap())
        .expect("write wallet");
}

fn contract_id(issuer_owner_key: &Hash256) -> Hash256 {
    boundary_hash("uv/contract/v1", &[issuer_owner_key, TICKER.as_bytes()])
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Address { wallet } => cmd_address(&cli.home, &wallet),
        Cmd::Issue { wallet, amount } => cmd_issue(&cli.home, &wallet, amount),
        Cmd::Send { wallet, to, amount, allow_respend } => {
            cmd_send(&cli.home, &wallet, &to, amount, allow_respend)
        }
        Cmd::Scan { wallet } => cmd_scan(&cli.home, &wallet),
        Cmd::Balance { wallet } => cmd_balance(&cli.home, &wallet),
    }
}

fn cmd_address(home: &Path, wallet: &str) {
    let (id, store) = load_or_create_wallet(home, wallet);
    save_wallet(home, wallet, &id, &store); // persist seed if new
    println!("{}", id.address_string());
}

fn cmd_balance(home: &Path, wallet: &str) {
    let (_, store) = load_or_create_wallet(home, wallet);
    println!("{wallet}: {} {TICKER} ({} unspent notes)", store.balance(), store.unspent().count());
}

fn cmd_issue(home: &Path, wallet: &str, amount: u64) {
    let (id, mut store) = load_or_create_wallet(home, wallet);
    let cid = contract_id(&id.owner_key());

    // Genesis: spend an axiomatic mint note into a holding note the wallet owns.
    let mint = Note {
        contract_id: cid,
        value: amount,
        owner_key: id.owner_key(),
        randomness: rand::random(),
    };
    let holding = Note {
        contract_id: cid,
        value: amount,
        owner_key: id.owner_key(),
        randomness: rand::random(),
    };
    let transfer = Transfer {
        inputs: vec![SpendInput { note: mint, nullifier_key: id.nullifier_key() }],
        outputs: vec![holding.clone()],
    };
    validate_transition(&transfer).expect("genesis conserves");

    eprintln!("proving genesis (issuance of {amount} {TICKER})…");
    let prover = Prover::new();
    let proved = prover.prove_genesis(&transfer).expect("prove genesis");

    store.add(OwnedNote {
        note: holding,
        proof_bytes: proved.proof_bytes,
        hop_output_bytes: proved.hop_output_bytes,
        spent: false,
    });
    save_wallet(home, wallet, &id, &store);
    println!("issued {amount} {TICKER} into {wallet}; balance {}", store.balance());
}

fn cmd_send(home: &Path, wallet: &str, to: &str, amount: u64, allow_respend: bool) {
    let (id, mut store) = load_or_create_wallet(home, wallet);
    let recipient = parse_address(to).expect("valid uv1 address");

    // Single-input coin selection (multi-input is a later refinement). Under
    // --allow-respend, deliberately re-select an already-spent note to stage a
    // double-spend the chain must reject downstream.
    let idx = if allow_respend {
        store
            .find_spent_spendable(amount)
            .or_else(|| store.find_spendable(amount))
            .expect("no note covers the amount")
    } else {
        store.find_spendable(amount).expect("no single note covers the amount")
    };
    let input = store.notes[idx].clone();
    let cid = input.note.contract_id;
    let change = input.note.value - amount;

    let recipient_note = Note {
        contract_id: cid,
        value: amount,
        owner_key: recipient.owner_key,
        randomness: rand::random(),
    };
    let change_note = Note {
        contract_id: cid,
        value: change,
        owner_key: id.owner_key(),
        randomness: rand::random(),
    };
    let mut outputs = vec![recipient_note.clone()];
    if change > 0 {
        outputs.push(change_note.clone());
    }
    let transfer = Transfer {
        inputs: vec![SpendInput { note: input.note.clone(), nullifier_key: id.nullifier_key() }],
        outputs,
    };
    let result = validate_transition(&transfer).expect("transfer conserves");

    eprintln!("proving transfer of {amount} {TICKER} → {}…", &to[..16.min(to.len())]);
    let prover = Prover::new();
    let prev = ProvedHop {
        proof_bytes: input.proof_bytes.clone(),
        hop_output_bytes: input.hop_output_bytes.clone(),
    };
    let proved = prover.prove_chained(&transfer, &prev).expect("prove chained");

    // Publish the 64-byte record; post the encrypted bundle to the recipient.
    let bh = bundle_hash(&result.canonical_bytes());
    let record = Record { nf: Nullifier(result.nullifiers[0]), bundle_hash: bh };
    let chain = FileChain::new(chain_path(home));
    let loc = chain.publish(&record);

    let bundle = Bundle {
        proof_bytes: proved.proof_bytes.clone(),
        hop_output_bytes: proved.hop_output_bytes.clone(),
        output_note: recipient_note,
        record: record.to_bytes().to_vec(),
    };
    let ciphertext = bundle.seal_to(&recipient.scan_public);
    let transport = FileTransport::new(mailbox_dir(home));
    transport.post(&scan_tag_for(&recipient.owner_key), &ciphertext);

    if allow_respend {
        // Double-spend demo: we attempted a conflicting spend on-chain but must
        // not touch our own books (the note was already spent-and-accounted).
        println!(
            "DOUBLE-SPEND ATTEMPT: re-published nf {}… (chain kept the first occurrence)",
            hex::encode(&result.nullifiers[0][..6])
        );
    } else {
        // Update our own state: input spent, change kept (chained on the new proof).
        store.mark_spent(idx);
        if change > 0 {
            store.add(OwnedNote {
                note: change_note,
                proof_bytes: proved.proof_bytes,
                hop_output_bytes: proved.hop_output_bytes,
                spent: false,
            });
        }
        save_wallet(home, wallet, &id, &store);
        println!(
            "sent {amount} {TICKER}; record at height {} (nf {}…); change {change}",
            loc.height,
            hex::encode(&result.nullifiers[0][..6])
        );
    }
}

fn cmd_scan(home: &Path, wallet: &str) {
    let (id, mut store) = load_or_create_wallet(home, wallet);
    let transport = FileTransport::new(mailbox_dir(home));
    let chain = FileChain::new(chain_path(home));
    let prover = Prover::new();

    let mine = id.owner_key();
    let delivered = transport.fetch(&scan_tag_for(&mine));
    let mut accepted = 0;
    let mut rejected = 0;

    for d in delivered {
        let Some(bundle) = Bundle::open_with(id.scan_secret(), &d.ciphertext) else {
            continue; // not for us
        };
        // Skip anything we already hold (content-addressed by output commitment).
        let out_commit = bundle.output_note.commitment().0;
        if store.notes.iter().any(|n| n.note.commitment().0 == out_commit) {
            continue;
        }
        // 1. Verify the one recursive proof.
        let proved = ProvedHop {
            proof_bytes: bundle.proof_bytes.clone(),
            hop_output_bytes: bundle.hop_output_bytes.clone(),
        };
        let hop = match prover.verify(&proved) {
            Ok(h) => h,
            Err(_) => {
                rejected += 1;
                continue;
            }
        };
        let result = &hop.public.result;

        // 2. The paid note must be ours and attested by the proof.
        if bundle.output_note.owner_key != mine
            || !result.output_commitments.contains(&out_commit)
        {
            rejected += 1;
            continue;
        }

        // 3. First-occurrence: the on-chain record for this transfer's nullifier
        //    must be THIS transfer (bundle-hash match). A double-spend loses here.
        let expected_bh = bundle_hash(&result.canonical_bytes());
        let nf = result.nullifiers[0];
        match chain.first_occurrence(&nf) {
            Some((rec, _)) if rec.bundle_hash == expected_bh => {}
            _ => {
                println!("  rejected a bundle: nullifier's first occurrence is a different transfer (double-spend)");
                rejected += 1;
                continue;
            }
        }

        store.add(OwnedNote {
            note: bundle.output_note,
            proof_bytes: bundle.proof_bytes,
            hop_output_bytes: bundle.hop_output_bytes,
            spent: false,
        });
        accepted += 1;
    }
    save_wallet(home, wallet, &id, &store);
    println!(
        "{wallet}: accepted {accepted}, rejected {rejected}; balance {} {TICKER}",
        store.balance()
    );
}
