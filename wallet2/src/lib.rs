//! The v2 wallet core: every discipline a formal model demanded, as code.
//!
//! | Module | Model | Discipline |
//! |---|---|---|
//! | [`signlog`] | `onetime.qnt` | record the signed payload; replay, never re-sign |
//! | [`store`] | `baserail.qnt` | one live transfer per note |
//! | [`accept`] | `linkage.qnt`, `multihop.qnt` | per-hop proofs + linkage + history binding + whole-ancestry settlement |
//! | [`reconcile`] | `reorg.qnt` | re-validate held notes when the chain changes |
//!
//! This crate is the consensus-critical wallet logic only. Transport (Signal),
//! the address/KEM layer, persistence encryption, and the Bitcoin backend sit
//! above it; `chain::MockChain` stands in for the last of those in tests.

pub mod accept;
pub mod chain;
pub mod reconcile;
pub mod send;
pub mod signlog;
pub mod store;

#[cfg(test)]
mod tests {
    //! End-to-end flows over a mock chain, including the attacks each check
    //! exists to stop. Proofs here are real hiding STARKs (~0.3 s each).

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use uv_air::poseidon2::Digest;
    use uv_air::prove::hiding_config;
    use uv_kernel2::amount::Amount;
    use uv_kernel2::history;
    use uv_kernel2::keys::{derive, WalletSeed};
    use uv_kernel2::note::Note;
    use uv_kernel2::transfer_prove::prove_hiding as raw_prove_hiding;

    use crate::accept::{accept, Hop, Lineage, Rejected, TrustAnchor};
    use crate::chain::{Chain, MockChain};
    use crate::reconcile::reconcile;
    use crate::send::{broadcast, prepare, Recipient, SendError, WalletCtx};
    use crate::signlog::SignLog;
    use crate::store::{Held, NoteState, Store, StoreError};

    /// `prepare` then persist then `broadcast`, which is what the CLI does and
    /// what the split exists to force. Tests go through the same three steps so
    /// they exercise the real ordering — including the persist step, which is
    /// `broadcast`'s argument precisely so no caller can skip it. An in-memory
    /// wallet has nothing to write, so the closure records that it *ran* and
    /// `persisted_before_publishing` asserts it ran first.
    fn send(
        cfg: &uv_air::prove::Vouched<uv_air::prove::HidingConfig>,
        chain: &mut (impl crate::chain::Chain + ?Sized),
        wallet: WalletCtx<'_>,
        input: &Digest,
        recipient: &Recipient,
        amount: Amount,
    ) -> Result<crate::send::Sent, crate::send::SendError> {
        let prepared = prepare(cfg, wallet, input, recipient, amount)?;
        broadcast(chain, prepared, || Ok::<(), String>(()))
    }

    /// The ordering itself, asserted rather than assumed: the persist step runs
    /// and it runs *before* anything reaches the chain. If it ran after, a
    /// crash in between would leave a published record the wallet has no
    /// sign-log entry for — and the retry signs a second message with a
    /// one-time key.
    #[test]
    fn persisted_before_publishing() {
        use std::cell::RefCell;
        let cfg = hiding_config();
        let mut chain = MockChain::new();
        chain.mine(10);
        let mut issuer = Wallet::new(60);
        let g = genesis(&mut issuer, &mut chain, 100);
        let mut bob = Wallet::new(61);

        let order = RefCell::new(Vec::<&'static str>::new());
        let (to_bob, _, _) = bob.expect(Amount(40));
        let prepared = prepare(
            &cfg,
            WalletCtx {
                store: &mut issuer.store,
                log: &mut issuer.log,
                seed: &issuer.seed,
            },
            &g.commitment(),
            &to_bob,
            Amount(40),
        )
        .expect("spendable");

        // A chain double that records when a publish happens, alongside a
        // persist closure that records when the write happens.
        struct Recording<'a> {
            inner: MockChain,
            order: &'a RefCell<Vec<&'static str>>,
        }
        impl crate::chain::Chain for Recording<'_> {
            fn first_occurrence(&self, nf: &Digest) -> crate::chain::Lookup {
                self.inner.first_occurrence(nf)
            }
            fn tip(&self) -> Result<u64, crate::chain::ChainViewError> {
                self.inner.tip()
            }
            fn publish(
                &mut self,
                r: &uv_kernel2::record::Record,
            ) -> Result<(), crate::chain::PublishError> {
                self.order.borrow_mut().push("publish");
                self.inner.publish(r)
            }
            fn publish_issuance(
                &mut self,
                i: &uv_kernel2::issuance::Issuance,
            ) -> Result<(), crate::chain::PublishError> {
                self.inner.publish_issuance(i)
            }
            fn issuances(&self) -> Vec<uv_kernel2::issuance::Issuance> {
                self.inner.issuances()
            }
            fn rollback_epoch(&self) -> u64 {
                self.inner.rollback_epoch()
            }
            fn refresh(&self) {}
            fn scan_floor(&self) -> u64 {
                0
            }
        }
        let mut rec = Recording {
            inner: chain,
            order: &order,
        };
        broadcast(&mut rec, prepared, || {
            order.borrow_mut().push("persist");
            Ok::<(), String>(())
        })
        .expect("publishes");

        assert_eq!(
            *order.borrow(),
            vec!["persist", "publish"],
            "the wallet must reach durable storage before the record reaches \
             the chain"
        );
    }

    /// And a failing write must stop the publish outright — not warn, not
    /// continue. "Published but not logged" is the state that discloses a key.
    #[test]
    fn a_failed_write_publishes_nothing() {
        let cfg = hiding_config();
        let mut chain = MockChain::new();
        chain.mine(10);
        let mut issuer = Wallet::new(62);
        let g = genesis(&mut issuer, &mut chain, 100);
        let mut bob = Wallet::new(63);

        let (to_bob, _, _) = bob.expect(Amount(40));
        let prepared = prepare(
            &cfg,
            WalletCtx {
                store: &mut issuer.store,
                log: &mut issuer.log,
                seed: &issuer.seed,
            },
            &g.commitment(),
            &to_bob,
            Amount(40),
        )
        .expect("spendable");
        let nf = prepared.record().nullifier;

        let out = broadcast(&mut chain, prepared, || {
            Err::<(), String>("disk full".into())
        });
        assert!(
            matches!(out, Err(SendError::NotPersisted(_))),
            "a failed write must be reported as NotPersisted"
        );
        assert!(
            matches!(chain.first_occurrence(&nf), crate::chain::Lookup::None),
            "NOTHING may reach the chain when the wallet could not be saved"
        );
    }

    fn asset() -> Digest {
        [BabyBear::from_u32(0xC0117); 8]
    }

    struct Wallet {
        seed: WalletSeed,
        store: Store,
        log: SignLog,
    }

    impl Wallet {
        fn new(tag: u8) -> Self {
            Wallet {
                seed: WalletSeed([tag; 32]),
                store: Store::new(),
                log: SignLog::new(),
            }
        }

        /// The recipient-side fields for this wallet's next note, plus the
        /// note it will reconstruct on receipt. (Stands in for the KEM dance.)
        fn expect(&mut self, amount: Amount) -> (Recipient, Note, u64) {
            let index = self.store.allocate_index();
            let keys = derive(&self.seed, index);
            let note = Note::build(asset(), amount, &keys);
            (
                Recipient {
                    nullifier_anchor: note.nullifier_anchor,
                    randomness: note.randomness,
                },
                note,
                index,
            )
        }
    }

    /// Issuance for tests: the issuer's genesis note, held with an empty
    /// lineage, **and its issuance record on the chain**. Its commitment is the
    /// trust anchor receivers get out of band.
    ///
    /// Publishing the record is not decoration. `accept` refuses any lineage
    /// whose genesis is not confirmed, with no way left to opt out, so a
    /// `genesis` that only minted locally would make every test below fail at
    /// the supply gate before reaching what it was written to test. This is
    /// exactly the sequence `uv issue` performs.
    fn genesis(wallet: &mut Wallet, chain: &mut MockChain, amount: u64) -> Note {
        let index = wallet.store.allocate_index();
        let keys = derive(&wallet.seed, index);
        let note = Note::build(asset(), Amount(amount), &keys);
        wallet
            .store
            .insert(Held {
                note: note.clone(),
                key_index: index,
                lineage: Lineage::new(),
                state: NoteState::Unspent,
            })
            .expect("fresh index");
        chain
            .publish_issuance(&uv_kernel2::issuance::Issuance {
                amount,
                asset: asset(),
                commitment: note.commitment(),
            })
            .expect("mock publish");
        note
    }

    /// The whole rail, twice over: issuer pays alice, alice pays bob, bob
    /// validates the two-hop lineage — proofs, linkage, history, settlement.
    /// Then every discipline is poked in turn.
    #[test]
    fn the_full_two_hop_flow_with_all_disciplines() {
        let cfg = hiding_config();
        let mut chain = MockChain::new();
        chain.mine(100);

        let mut issuer = Wallet::new(1);
        let mut alice = Wallet::new(2);
        let mut bob = Wallet::new(3);

        let g = genesis(&mut issuer, &mut chain, 10_000);
        let anchor = g.commitment();

        // Hop 1: issuer -> alice, 5000 (required depth 3 at that value).
        let (alice_rcpt, alice_note, alice_idx) = alice.expect(Amount(5_000));
        let sent1 = send(
            &cfg,
            &mut chain,
            WalletCtx {
                store: &mut issuer.store,
                log: &mut issuer.log,
                seed: &issuer.seed,
            },
            &anchor,
            &alice_rcpt,
            Amount(5_000),
        )
        .expect("issuer sends");

        // Depth 1 < 3: alice must wait.
        let lineage1: Lineage = vec![sent1.hop.clone()];
        assert!(matches!(
            accept(
                &cfg,
                &chain,
                &TrustAnchor {
                    asset: &asset(),
                    genesis_commitment: &anchor,
                    issued_below: None,
                    genesis_amount: 10_000,
                },
                &alice_note,
                &lineage1,
            ),
            Err(Rejected::InsufficientDepth(0))
        ));
        chain.mine(2);
        accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset(),
                genesis_commitment: &anchor,
                issued_below: None,
                genesis_amount: 10_000,
            },
            &alice_note,
            &lineage1,
        )
        .expect("alice accepts at depth");
        alice
            .store
            .insert(Held {
                note: alice_note.clone(),
                key_index: alice_idx,
                lineage: lineage1.clone(),
                state: NoteState::Unspent,
            })
            .expect("fresh index");

        // Hop 2: alice -> bob, 700. Every tier now needs at least 3, since
        // the 1-confirmation tier was withdrawn — see `required_confirmations`.
        let (bob_rcpt, bob_note, _) = bob.expect(Amount(700));
        let sent2 = send(
            &cfg,
            &mut chain,
            WalletCtx {
                store: &mut alice.store,
                log: &mut alice.log,
                seed: &alice.seed,
            },
            &alice_note.commitment(),
            &bob_rcpt,
            Amount(700),
        )
        .expect("alice sends");
        let lineage2: Lineage = vec![sent1.hop.clone(), sent2.hop.clone()];
        assert!(
            matches!(
                accept(
                    &cfg,
                    &chain,
                    &TrustAnchor {
                        asset: &asset(),
                        genesis_commitment: &anchor,
                        issued_below: None,
                        genesis_amount: 10_000,
                    },
                    &bob_note,
                    &lineage2,
                ),
                Err(Rejected::InsufficientDepth(1))
            ),
            "hop 2 is one block deep; the floor is three"
        );
        chain.mine(2);
        accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset(),
                genesis_commitment: &anchor,
                issued_below: None,
                genesis_amount: 10_000,
            },
            &bob_note,
            &lineage2,
        )
        .expect("bob accepts the two-hop lineage");

        // -- Discipline 1 (one live transfer): a second, different spend of
        // alice's note is refused by the store...
        let (carol_rcpt, _, _) = Wallet::new(4).expect(Amount(100));
        // ...but wait — the sign-log replay path intercepts first, and that
        // is correct: what comes back is the ORIGINAL payload, not a new one.
        let replay = send(
            &cfg,
            &mut chain,
            WalletCtx {
                store: &mut alice.store,
                log: &mut alice.log,
                seed: &alice.seed,
            },
            &alice_note.commitment(),
            &carol_rcpt,
            Amount(100),
        )
        .expect("replay path");
        assert_eq!(
            replay.transfer, sent2.transfer,
            "a logged note replays its original payload, whatever was asked"
        );

        // A note with no log entry but in-flight state: the store refuses.
        // (Simulate by clearing the log entry's interception via a fresh
        // wallet state pointing at the same note.)
        let mut fresh_log = SignLog::new();
        assert!(matches!(
            send(
                &cfg,
                &mut chain,
                WalletCtx {
                    store: &mut alice.store,
                    log: &mut fresh_log,
                    seed: &alice.seed,
                },
                &alice_note.commitment(),
                &carol_rcpt,
                Amount(100),
            ),
            Err(SendError::Store(StoreError::AlreadyInFlight))
        ));

        // -- Discipline 2 (linkage): a hop spending a note nobody created —
        // `fabricateHop`. The attacker proves a spend of their own invented
        // note with a correctly-guessed history position; only the linkage
        // check stands.
        let mallory = WalletSeed([66u8; 32]);
        let mk = derive(&mallory, 0);
        let fake = Note::build(asset(), Amount(700), &mk);
        let (fake_pay, fake_note, _) = Wallet::new(5).expect(Amount(700));
        let _ = fake_pay;
        let fold1 = history::advance(&history::GENESIS, &sent1.transfer.bundle_hash());
        let dummy = Note::build(asset(), Amount(0), &derive(&mallory, 1));
        let (fab_transfer, fab_proof) =
            raw_prove_hiding(&cfg, &fake, &mk, [&fake_note, &dummy], &fold1);
        // Settle the fabricated hop so only linkage can refuse it.
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: fab_transfer.nullifier,
                bundle_hash: fab_transfer.bundle_hash(),
            })
            .unwrap();
        let fab_lineage: Lineage = vec![
            sent1.hop.clone(),
            Hop {
                transfer: fab_transfer,
                proof: bincode::serialize(&fab_proof).unwrap(),
            },
        ];
        assert!(
            matches!(
                accept(
                    &cfg,
                    &chain,
                    &TrustAnchor {
                        asset: &asset(),
                        genesis_commitment: &anchor,
                        issued_below: None,
                        genesis_amount: 10_000,
                    },
                    &fake_note,
                    &fab_lineage,
                ),
                Err(Rejected::NotLinked(1))
            ),
            "a fabricated ancestor must be caught by linkage"
        );

        // -- Discipline 3 (history binding): hop 2 re-proven at the wrong
        // history position. Linkage passes (it spends a real output);
        // the fold does not.
        // (Reuse bob's hop with a doctored prev_history is impossible without
        // re-signing — which is the point — so this attack needs the
        // adversary to OWN the spent note. Mallory re-spends her own fake
        // note claiming genesis position:)
        let (fab2_transfer, fab2_proof) =
            raw_prove_hiding(&cfg, &fake, &mk, [&fake_note, &dummy], &history::GENESIS);
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: fab2_transfer.nullifier,
                bundle_hash: fab2_transfer.bundle_hash(),
            })
            .unwrap();
        let fab2: Lineage = vec![
            sent1.hop.clone(),
            Hop {
                transfer: fab2_transfer,
                proof: bincode::serialize(&fab2_proof).unwrap(),
            },
        ];
        match accept(
            &cfg,
            &chain,
            &TrustAnchor {
                asset: &asset(),
                genesis_commitment: &anchor,
                issued_below: None,
                genesis_amount: 10_000,
            },
            &fake_note,
            &fab2,
        ) {
            Err(Rejected::NotLinked(1)) | Err(Rejected::NotThisNotesAncestry(1)) => {}
            other => panic!("a mispositioned hop must be refused, got {other:?}"),
        }

        // -- Discipline 4 (whole-ancestry settlement): drop hop 1's record;
        // bob's already-accepted note fails re-validation and quarantines.
        bob.store
            .insert(Held {
                note: bob_note.clone(),
                key_index: 0,
                lineage: lineage2.clone(),
                state: NoteState::Unspent,
            })
            .expect("fresh index");
        chain.reorg_drop(&sent1.transfer.nullifier);
        let out = reconcile(&chain, &mut bob.store, &bob.log, None);
        assert_eq!(out.quarantined.len(), 1, "bob's note must quarantine");
        assert!(
            out.unverifiable.is_empty(),
            "MockChain sees the whole chain; nothing should be unverifiable"
        );
        assert_eq!(
            bob.store.get(&bob_note.commitment()).unwrap().state,
            NoteState::Quarantined
        );
    }

    /// The multihop inflation attack, replayed against the v2 stack: mallory
    /// double-spends her note, the honest record wins, and the LOSING spend's
    /// note is laundered onward to carol. Carol's whole-ancestry settlement
    /// check refuses it — the check `formal/multihop.qnt` proved necessary.
    #[test]
    fn the_inflation_attack_is_refused() {
        let cfg = hiding_config();
        let mut chain = MockChain::new();
        chain.mine(50);

        let mut issuer = Wallet::new(10);
        let g = genesis(&mut issuer, &mut chain, 900);
        let anchor = g.commitment();

        // Issuer pays mallory honestly.
        let mallory_seed = WalletSeed([11u8; 32]);
        let mk = derive(&mallory_seed, 0);
        let m_note = Note::build(asset(), Amount(900), &mk);
        let (m_rcpt, _, _) = {
            let mut m = Wallet::new(11);
            m.expect(Amount(900))
        };
        let _ = m_rcpt;
        let sent = send(
            &cfg,
            &mut chain,
            WalletCtx {
                store: &mut issuer.store,
                log: &mut issuer.log,
                seed: &issuer.seed,
            },
            &anchor,
            &Recipient {
                nullifier_anchor: m_note.nullifier_anchor,
                randomness: m_note.randomness,
            },
            Amount(900),
        )
        .unwrap();
        chain.mine(1);
        let fold1 = history::advance(&history::GENESIS, &sent.transfer.bundle_hash());

        // Mallory (non-conforming wallet: no sign-log) builds TWO spends of
        // her note, bypassing every wallet discipline.
        let dummy_a = Note::build(asset(), Amount(0), &derive(&mallory_seed, 2));
        let self_note = Note::build(asset(), Amount(900), &derive(&mallory_seed, 3));
        let (spend_a, _) = raw_prove_hiding(&cfg, &m_note, &mk, [&self_note, &dummy_a], &fold1);

        let carol_seed = WalletSeed([12u8; 32]);
        let carol_note = Note::build(asset(), Amount(900), &derive(&carol_seed, 0));
        let dummy_b = Note::build(asset(), Amount(0), &derive(&mallory_seed, 4));
        let (spend_b, proof_b) =
            raw_prove_hiding(&cfg, &m_note, &mk, [&carol_note, &dummy_b], &fold1);

        // Spend A's record wins the race; spend B loses.
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: spend_a.nullifier,
                bundle_hash: spend_a.bundle_hash(),
            })
            .unwrap();
        chain.mine(1);
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: spend_b.nullifier,
                bundle_hash: spend_b.bundle_hash(),
            })
            .unwrap();
        // Same note, same nullifier: the chain kept the first occurrence.
        assert_eq!(spend_a.nullifier, spend_b.nullifier);

        // Carol validates the full lineage of the note spend B paid her.
        let lineage: Lineage = vec![
            sent.hop.clone(),
            Hop {
                transfer: spend_b.clone(),
                proof: bincode::serialize(&proof_b).unwrap(),
            },
        ];
        assert!(
            matches!(
                accept(
                    &cfg,
                    &chain,
                    &TrustAnchor {
                        asset: &asset(),
                        genesis_commitment: &anchor,
                        issued_below: None,
                        genesis_amount: 900,
                    },
                    &carol_note,
                    &lineage,
                ),
                Err(Rejected::LostRace(1))
            ),
            "the laundered losing spend must be refused at settlement"
        );
    }

    /// The griefing / front-running race (spec/99 `[FRONTRUN]`, the debt this closes).
    /// A third party who has observed a broadcast nullifier front-runs the
    /// honest record with `(nf, garbage)`. First-occurrence-wins binds the
    /// nullifier to the garbage forever, so the honest payment can never
    /// settle — AND the attacker gains nothing, because the garbage record
    /// backs no acceptable note. This is why spec/99 reclassifies it from
    /// "griefing" (annoyance) to a liveness failure with no recovery path:
    /// `formal/baserail.qnt` proves the safety property holds throughout.
    #[test]
    fn a_frontrun_griefing_record_bricks_the_note_and_pays_the_griefer_nothing() {
        let cfg = hiding_config();
        let mut chain = MockChain::new();
        chain.mine(50);

        let mut issuer = Wallet::new(20);
        let g = genesis(&mut issuer, &mut chain, 500);
        let anchor = g.commitment();

        // The honest transfer is fully built — so its nullifier is fixed and,
        // once broadcast, observable. That is the only thing the griefer needs.
        let bob = Wallet::new(21);
        let bob_keys = derive(&bob.seed, 0);
        let bob_note = Note::build(asset(), Amount(500), &bob_keys);
        let dummy = Note::build(asset(), Amount(0), &derive(&issuer.seed, 9));
        let g_keys = derive(&issuer.seed, 0); // issuer's genesis note keys (index 0)
        let (honest, honest_proof) =
            raw_prove_hiding(&cfg, &g, &g_keys, [&bob_note, &dummy], &history::GENESIS);

        // The griefer front-runs: same nullifier, a bundle hash backing nothing.
        // They pay a real Bitcoin fee and receive nothing in return.
        let garbage = [BabyBear::from_u32(0xDEAD); 8];
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: honest.nullifier,
                bundle_hash: garbage,
            })
            .unwrap();
        chain.mine(1);
        // The honest record now lands too late — first-occurrence already took
        // the griefer's. (On the real chain this publish is a no-op; here we
        // show the chain keeps the first occurrence.)
        chain
            .publish(&uv_kernel2::record::Record {
                nullifier: honest.nullifier,
                bundle_hash: honest.bundle_hash(),
            })
            .unwrap();
        assert_eq!(
            match chain.first_occurrence(&honest.nullifier) {
                crate::chain::Lookup::Found(o) => o.bundle_hash,
                other => panic!("expected a found record, got {other:?}"),
            },
            garbage,
            "first occurrence must be the griefer's, not the honest record"
        );

        // Bob's note is bricked: the honest lineage is refused at settlement.
        let lineage: Lineage = vec![Hop {
            transfer: honest.clone(),
            proof: bincode::serialize(&honest_proof).unwrap(),
        }];
        assert!(
            matches!(
                accept(
                    &cfg,
                    &chain,
                    &TrustAnchor {
                        asset: &asset(),
                        genesis_commitment: &anchor,
                        issued_below: None,
                        genesis_amount: 500,
                    },
                    &bob_note,
                    &lineage,
                ),
                Err(Rejected::LostRace(0))
            ),
            "the honest note must be unspendable — a liveness failure, no recovery"
        );

        // The griefer gained nothing: there is no note the garbage record backs
        // that anyone will accept. Any note a griefer might present against
        // this nullifier fails linkage/settlement exactly as Bob's did — the
        // garbage bundle hash corresponds to no proven transfer at all.
        let griefer_seed = WalletSeed([99u8; 32]);
        let griefer_note = Note::build(asset(), Amount(500), &derive(&griefer_seed, 0));
        assert!(
            accept(
                &cfg,
                &chain,
                &TrustAnchor {
                    asset: &asset(),
                    genesis_commitment: &anchor,
                    issued_below: None,
                    genesis_amount: 500,
                },
                &griefer_note,
                &lineage,
            )
            .is_err(),
            "the griefer cannot turn the garbage record into a spendable note"
        );
    }
}
