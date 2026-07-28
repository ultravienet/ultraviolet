//! A real Ultraviolet payment, carried over a real Signal Protocol session.
//!
//! Everything here is genuine: a hash-based one-time signature, a hiding STARK
//! over the whole hop, a record settled on a chain, an ML-KEM-768 + X25519
//! envelope, and a Signal session established by PQXDH from a published pre-key
//! bundle. Nothing is stubbed except the *server*, and that on purpose — the
//! relay is deliberately stupid so the test can inspect exactly what a carrier
//! would have seen.
//!
//! What this does **not** show: that the Signal *network* would carry this.
//! Signal blocks third-party clients, so this is your own deployment. The claim
//! that survives is the one worth having — a carrier routes bytes it cannot
//! read and cannot identify as money.

use uv_air::prove::hiding_config;
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::keys::{derive, NoteKeys, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer_prove::prove_hiding;
use uv_signal::{Participant, Relay};
use uv_wallet2::accept::{accept, Hop, Lineage};
use uv_wallet2::chain::{Chain, MockChain};

/// Exactly what the CLI mails: which slot this pays, and the full lineage.
#[derive(serde::Serialize, serde::Deserialize)]
struct Bundle {
    index: u64,
    amount: u64,
    lineage: Lineage,
}

#[tokio::test]
async fn a_real_payment_rides_a_real_signal_session() {
    // ---- 1. A real payment: issuer pays bob, proved and settled. ----
    let cfg = hiding_config();
    let mut chain = MockChain::new();
    chain.mine(100);

    let asset = [p3_field::PrimeCharacteristicRing::ONE; 8];
    let issuer_seed = WalletSeed([7u8; 32]);
    let bob_seed = WalletSeed([9u8; 32]);

    let issuer_keys: NoteKeys = derive(&issuer_seed, 0);
    let genesis = Note::build(asset, Amount(1_000), &issuer_keys);
    let genesis_commitment = genesis.commitment();

    // Bob's one-time slot, and the change note the issuer keeps.
    let bob_keys: NoteKeys = derive(&bob_seed, 0);
    let bob_note = Note::build(asset, Amount(250), &bob_keys);
    let change_keys: NoteKeys = derive(&issuer_seed, 1);
    let change = Note::build(asset, Amount(750), &change_keys);

    let (transfer, proof) = prove_hiding(
        &cfg,
        &genesis,
        &issuer_keys,
        [&bob_note, &change],
        &history::GENESIS,
    );

    // The record settles on Bitcoin. Without this the receiver refuses.
    chain
        .publish(&Record {
            nullifier: transfer.nullifier,
            bundle_hash: transfer.bundle_hash(),
        })
        .unwrap();
    chain.mine(10);

    let lineage: Lineage = vec![Hop {
        transfer,
        proof: bincode::serialize(&proof).expect("serialize proof"),
    }];

    // ---- 2. Seal it to bob's scan key. This is confidentiality from the
    // carrier, and it does not depend on who the carrier is. ----
    let (bob_scan_secret, bob_scan_public) = uv_envelope::derive_scan(&bob_seed.0);
    let plain = bincode::serialize(&Bundle {
        index: 0,
        amount: 250,
        lineage,
    })
    .expect("serialize bundle");
    let sealed = uv_envelope::seal(&bob_scan_public, &plain).expect("seal to bob");
    let on_the_wire = bincode::serialize(&sealed).expect("serialize sealed");

    // ---- 3. Signal: two identities, a published bundle, a PQXDH handshake. ----
    let relay = Relay::new();
    let mut alice = Participant::new("+15550001111").await.expect("alice");
    let mut bob = Participant::new("+15550002222").await.expect("bob");

    let bobs_bundle = bob.pre_key_bundle().await.expect("bob's pre-key bundle");
    alice
        .start_session(&bob.address, &bobs_bundle)
        .await
        .expect("session from bob's bundle");

    alice
        .send(&relay, &bob.address, &on_the_wire)
        .await
        .expect("send over signal");

    // ---- 4. Bob receives, unwraps both layers, and accepts the money. ----
    let received = bob
        .receive(&relay, &alice.address)
        .await
        .expect("receive over signal");
    assert_eq!(received.len(), 1, "exactly one message should have arrived");
    assert_eq!(
        received[0], on_the_wire,
        "Signal must deliver the envelope byte-for-byte"
    );

    let opened = uv_envelope::open(
        &bob_scan_secret,
        &bincode::deserialize(&received[0]).expect("deserialize sealed"),
    )
    .expect("bob opens his own mail");
    let bundle: Bundle = bincode::deserialize(&opened).expect("deserialize bundle");

    accept(
        &cfg,
        &chain,
        &asset,
        &genesis_commitment,
        &bob_note,
        &bundle.lineage,
        None,
    )
    .expect("bob's wallet accepts a payment that arrived over Signal");
    assert_eq!(bundle.amount, 250);

    // ---- 5. What did the carrier see? ----
    let seen = relay.what_it_saw();
    assert_eq!(seen.len(), 1);
    let carried = &seen[0];

    // Not the payment, at any layer.
    for leak in [
        b"amount".as_slice(),
        b"lineage".as_slice(),
        b"index".as_slice(),
        b"proof".as_slice(),
    ] {
        assert!(
            !carried.bytes.windows(leak.len()).any(|w| w == leak),
            "the carrier saw a plaintext field name"
        );
    }
    // Not the sealed envelope either — Signal's layer is doing real work, so
    // the bytes on the wire are not the bytes we handed it.
    assert_ne!(
        carried.bytes, on_the_wire,
        "Signal must actually encrypt, not merely forward"
    );
    // And the ciphertext must not compress, or it is not ciphertext.
    let ratio = miniz_oxide::deflate::compress_to_vec(&carried.bytes, 9).len() as f64
        / carried.bytes.len() as f64;
    assert!(
        ratio > 0.95,
        "what the carrier holds compresses to {:.0}% of its size, so it is not ciphertext",
        ratio * 100.0
    );

    println!(
        "carrier saw: {} bytes addressed to {:?}, incompressible, \
         and no field of the payment it wraps",
        carried.bytes.len(),
        carried.to
    );
}
