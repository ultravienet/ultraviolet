//! The inflation attack from `formal/multihop.qnt`, replayed with real types.
//!
//! **This file is cited by the formal models as the bridge between the model
//! and the code, and for a while the citation was dead** — the file it named
//! had been deleted with the crate it lived in, while `formal/README.md` kept
//! naming it as the real-code replay. `formal/check-refs.sh` now fails CI if it
//! goes missing again.
//!
//! **The attack.** The model's question was whether checking first-occurrence
//! at your own hop composes into supply conservation. It does not, and the
//! counterexample is an 8-step laundering trace: the adversary spends one
//! ancestor twice — once recorded, once losing the first-occurrence race — and
//! then pays a victim out of the *losing* branch. The victim's own hop settles
//! perfectly: its record is first, deep, and matches. Everything wrong is one
//! hop upstream, where no per-hop check ever looks. Two wallets each running
//! the check correctly now hold notes descending from one coin.
//!
//! **What this pins.** Both halves of the model's verdict, against real notes,
//! real nullifiers, real hiding STARKs and a real `Chain`:
//!  - the own-hop check the model proved insufficient *would* accept the
//!    laundered note (asserted explicitly, so the insufficiency stays visible);
//!  - `accept`, which walks the whole ancestry (the fix, normative in
//!    `SPEC.md` §7), refuses it — and still accepts the honest branch.

use p3_baby_bear::BabyBear;

use uv_air::poseidon2::Digest;
use uv_air::prove::hiding_config;
use uv_kernel2::amount::Amount;
use uv_kernel2::history;
use uv_kernel2::keys::{derive, NoteKeys, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::record::Record;
use uv_kernel2::transfer_prove::prove_hiding;
use uv_wallet2::accept::{accept, Hop, Lineage, Rejected, TrustAnchor};
use uv_wallet2::chain::{Chain, Lookup, MockChain};

const ASSET: Digest = [BabyBear::new(0xA5); 8];

fn keys(seed: &WalletSeed, i: u64) -> NoteKeys {
    derive(seed, i)
}

#[test]
fn per_hop_settlement_does_not_compose_and_accept_knows_it() {
    let cfg = hiding_config();
    let mut chain = MockChain::new();
    chain.mine(50);

    // The adversary's genesis note G — the coin that will be two coins.
    let adversary = WalletSeed([13u8; 32]);
    let g_keys = keys(&adversary, 0);
    let g = Note::build(ASSET, Amount(100), &g_keys);
    let genesis_commitment = g.commitment();
    // Publish the genesis's issuance record. `accept` refuses any lineage whose
    // genesis is not confirmed on the chain it is reading, and there is no
    // longer a way to opt out of that check — so without this the test would
    // stop at the supply gate rather than reaching what it exists to prove.
    chain
        .publish_issuance(&uv_kernel2::issuance::Issuance {
            amount: 100,
            asset: ASSET,
            commitment: genesis_commitment,
        })
        .expect("mock publish");

    // T1: G -> A, the branch whose record will WIN first occurrence.
    let a_note = Note::build(ASSET, Amount(100), &keys(&adversary, 1));
    let zero1 = Note::build(ASSET, Amount(0), &keys(&adversary, 2));
    let (t1, t1_proof) = prove_hiding(&cfg, &g, &g_keys, [&a_note, &zero1], &history::GENESIS);

    // T2: G -> B, the same note spent AGAIN. A conforming wallet's sign-log
    // refuses this; the adversary is not running a conforming wallet, and the
    // kernel — correctly — only checks that the keys are the note's own.
    let b_note = Note::build(ASSET, Amount(100), &keys(&adversary, 3));
    let zero2 = Note::build(ASSET, Amount(0), &keys(&adversary, 4));
    let (t2, t2_proof) = prove_hiding(&cfg, &g, &g_keys, [&b_note, &zero2], &history::GENESIS);

    assert_eq!(
        t1.nullifier, t2.nullifier,
        "one note, one nullifier — that identity is what the race is about"
    );

    // T1's record lands first and binds the nullifier. T2's is inert.
    chain
        .publish(&Record {
            nullifier: t1.nullifier,
            bundle_hash: t1.bundle_hash(),
        })
        .unwrap();
    chain.mine(1);
    chain
        .publish(&Record {
            nullifier: t2.nullifier,
            bundle_hash: t2.bundle_hash(),
        })
        .unwrap();
    chain.mine(5);

    // T3: the adversary pays the victim out of the LOSING branch.
    let victim = WalletSeed([77u8; 32]);
    let v_keys = keys(&victim, 0);
    let v_note = Note::build(ASSET, Amount(100), &v_keys);
    let zero3 = Note::build(ASSET, Amount(0), &keys(&adversary, 5));
    let b_keys = keys(&adversary, 3);
    let t3_prev = history::digest_of(&[t2.bundle_hash()]);
    let (t3, t3_proof) = prove_hiding(&cfg, &b_note, &b_keys, [&v_note, &zero3], &t3_prev);
    chain
        .publish(&Record {
            nullifier: t3.nullifier,
            bundle_hash: t3.bundle_hash(),
        })
        .unwrap();
    chain.mine(5);

    // THE MODEL'S POINT, kept visible: the victim's own hop looks perfect.
    // Its record is the first occurrence, matches its bundle, and is deep.
    // A wallet that checked only this — as the wallet did when the model was
    // written — accepts money from a double-spend it cannot see.
    match chain.first_occurrence(&t3.nullifier) {
        Lookup::Found(occ) => {
            assert_eq!(occ.bundle_hash, t3.bundle_hash(), "own hop: bundle matches");
            assert!(occ.depth >= 3, "own hop: deep enough");
        }
        other => panic!("the victim's own record must have settled: {other:?}"),
    }

    // The whole-ancestry check refuses: hop 0 of the victim's lineage is T2,
    // and the first occurrence of its nullifier is T1's record.
    let laundered: Lineage = vec![
        Hop {
            transfer: t2.clone(),
            proof: bincode::serialize(&t2_proof).unwrap(),
        },
        Hop {
            transfer: t3.clone(),
            proof: bincode::serialize(&t3_proof).unwrap(),
        },
    ];
    let verdict = accept(
        &cfg,
        &chain,
        &TrustAnchor {
            asset: &ASSET,
            genesis_commitment: &genesis_commitment,
            issued_below: None,
            genesis_amount: 100,
        },
        &v_note,
        &laundered,
    );
    assert!(
        matches!(verdict, Err(Rejected::LostRace(0))),
        "INFLATION: the laundered branch was accepted (or refused for the \
         wrong reason): {verdict:?}"
    );

    // And the honest branch still spends — refusing both would be a different
    // bug. One coin, one surviving branch: supply conserved.
    let honest: Lineage = vec![Hop {
        transfer: t1.clone(),
        proof: bincode::serialize(&t1_proof).unwrap(),
    }];
    accept(
        &cfg,
        &chain,
        &TrustAnchor {
            asset: &ASSET,
            genesis_commitment: &genesis_commitment,
            issued_below: None,
            genesis_amount: 100,
        },
        &a_note,
        &honest,
    )
    .expect("the branch that won its race is good money");
}
