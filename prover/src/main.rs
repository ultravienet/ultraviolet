//! Two-hop proof-carrying data: the O(1)-receive demo.
//!
//! Hop 1 (genesis): 100 → 60 + 40, proven compressed.
//! Hop 2 (chained): spends the 60-note; its proof VERIFIES HOP 1'S PROOF
//! IN-CIRCUIT, so the receiver checks exactly one proof for the whole
//! history. SLH-DSA spend authorization stays host-side in v0.
//!
//! Also proves hop 1 in core mode once, for the size comparison table.
//!
//! Run: `cargo run --release -p uv-prover`

use std::time::Instant;

use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Proof, SP1Stdin,
};
use ultraviolet_kernel::hash::boundary_hash;
use ultraviolet_kernel::history::{
    advance_history, HopInput, HopOutput, GENESIS_DIGEST,
};
use ultraviolet_kernel::nullifier::{bundle_hash, Record};
use ultraviolet_kernel::sig::slh::SlhKeypair;
use ultraviolet_kernel::sig::{Signer, Verifier};
use ultraviolet_kernel::transfer::{validate_transition, SpendInput, Transfer};
use ultraviolet_kernel::{Note, Nullifier};

const GUEST_ELF: Elf = include_elf!("uv-guest");

fn main() {
    sp1_sdk::utils::setup_logger();

    // --- The two transfers. Hop 2 spends hop 1's 60-unit output. ---
    let contract_id = boundary_hash("uv/demo-contract/v1", &[b"UVD genesis"]);
    let owner = SlhKeypair::generate().expect("keygen");
    let owner_key = boundary_hash("uv/owner-key/v1", &[&owner.public_key_bytes()]);

    let hop1_out_a = Note { contract_id, value: 60, owner_key, randomness: [22; 32] };
    let hop1_out_b = Note { contract_id, value: 40, owner_key: [31; 32], randomness: [32; 32] };
    let t1 = Transfer {
        inputs: vec![SpendInput {
            note: Note { contract_id, value: 100, owner_key: [11; 32], randomness: [7; 32] },
            nullifier_key: [9; 32],
        }],
        outputs: vec![hop1_out_a.clone(), hop1_out_b],
    };
    let t2 = Transfer {
        inputs: vec![SpendInput { note: hop1_out_a, nullifier_key: [10; 32] }],
        outputs: vec![
            Note { contract_id, value: 25, owner_key: [41; 32], randomness: [42; 32] },
            Note { contract_id, value: 35, owner_key: [51; 32], randomness: [52; 32] },
        ],
    };

    // --- Host-side SLH-DSA spend authorization for hop 2 (v0 scope). ---
    let r2_expected = validate_transition(&t2).expect("hop 2 valid");
    let bh = bundle_hash(&r2_expected.canonical_bytes());
    let sig = owner.sign(&bh);
    assert!(owner.public_key().verify(&bh, &sig), "spend authorization must verify");
    let record = Record { nf: Nullifier(r2_expected.nullifiers[0]), bundle_hash: bh };
    println!(
        "hop 2 spend authorized: SLH-DSA-128s sig {} B; on-chain record {} B",
        sig.len(),
        record.to_bytes().len()
    );

    // --- Prover setup. ---
    let client = ProverClient::from_env();
    let pk = client.setup(GUEST_ELF).expect("setup");
    let vkey = pk.verifying_key().hash_u32();

    // --- Hop 1: core once (size comparison), then compressed (for recursion). ---
    let mut stdin1 = SP1Stdin::new();
    stdin1.write(&HopInput::Genesis { transfer: t1.clone(), vkey });

    let t = Instant::now();
    let core1 = client.prove(&pk, stdin1.clone()).run().expect("hop1 core prove");
    let core1_secs = t.elapsed().as_secs_f64();
    let core1_kb = proof_kb(&core1, "uv-hop1-core");

    let t = Instant::now();
    let hop1 = client.prove(&pk, stdin1).compressed().run().expect("hop1 compressed prove");
    let hop1_secs = t.elapsed().as_secs_f64();
    let hop1_kb = proof_kb(&hop1, "uv-hop1-compressed");

    let hop1_out = HopOutput::decode(hop1.public_values.as_slice()).expect("hop1 output decodes");
    assert_eq!(hop1_out.vkey, vkey);
    println!(
        "hop 1 proven: core {core1_secs:.1}s/{core1_kb} KB, compressed {hop1_secs:.1}s/{hop1_kb} KB"
    );

    // --- Negative check: a hop 2 spending a stranger note must not execute. ---
    let bad_t2 = Transfer {
        inputs: vec![SpendInput {
            note: Note { contract_id, value: 60, owner_key, randomness: [99; 32] },
            nullifier_key: [10; 32],
        }],
        outputs: vec![Note { contract_id, value: 60, owner_key: [41; 32], randomness: [42; 32] }],
    };
    let mut bad_stdin = SP1Stdin::new();
    bad_stdin.write(&HopInput::Chained { transfer: bad_t2, prev: hop1_out.clone(), vkey });
    let SP1Proof::Compressed(p) = hop1.proof.clone() else { panic!("expected compressed") };
    bad_stdin.write_proof(*p, pk.verifying_key().clone().vk);
    let rejected = match client.execute(GUEST_ELF, bad_stdin).run() {
        Err(_) => true,
        // A panicked guest never reaches commit — no decodable output.
        Ok((pv, _)) => HopOutput::decode(pv.as_slice()).is_none(),
    };
    assert!(rejected, "linkage violation must be rejected in the guest");
    println!("linkage violation rejected by guest: OK");

    // --- Hop 2: chained, verifying hop 1's proof in-circuit. ---
    let mut stdin2 = SP1Stdin::new();
    stdin2.write(&HopInput::Chained { transfer: t2, prev: hop1_out.clone(), vkey });
    let SP1Proof::Compressed(p) = hop1.proof.clone() else { panic!("expected compressed") };
    stdin2.write_proof(*p, pk.verifying_key().clone().vk);

    let t = Instant::now();
    let hop2 = client.prove(&pk, stdin2).compressed().run().expect("hop2 compressed prove");
    let hop2_secs = t.elapsed().as_secs_f64();
    let hop2_kb = proof_kb(&hop2, "uv-hop2-compressed");

    // --- The receiver's entire job: verify ONE proof, check its chain. ---
    client.verify(&hop2, pk.verifying_key(), None).expect("hop 2 verifies");
    let hop2_out = HopOutput::decode(hop2.public_values.as_slice()).expect("hop2 output decodes");
    assert_eq!(hop2_out.vkey, vkey, "vkey constant along the chain");
    assert_eq!(hop2_out.public.result, r2_expected, "guest and host agree on hop 2");
    let expected_digest = advance_history(
        &advance_history(&GENESIS_DIGEST, &validate_transition(&t1).unwrap()),
        &r2_expected,
    );
    assert_eq!(hop2_out.public.history_digest, expected_digest, "history digest chains");

    println!("hop 2 proven (verifies hop 1 IN-CIRCUIT): {hop2_secs:.1}s/{hop2_kb} KB");
    println!(
        "receiver verified 2 hops with ONE {hop2_kb} KB proof — O(1) receive: OK"
    );
}

fn proof_kb(proof: &sp1_sdk::SP1ProofWithPublicValues, name: &str) -> u64 {
    let path = std::env::temp_dir().join(format!("{name}.bin"));
    proof.save(&path).expect("save proof");
    std::fs::metadata(&path).map(|m| m.len() / 1024).unwrap_or(0)
}
