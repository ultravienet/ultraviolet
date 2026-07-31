//! The composed system, end to end: issuance → payment → replay → split →
//! two-hop → supply → reorg. `demo/local2.sh`, made a test.
//!
//! **Why this exists as Rust and not as the shell script it replaces.** The
//! demo drove the `uv` CLI; the CLI died with the client pivot to the Signal
//! fork. What must not die with it is the one layer that runs the system *as a
//! system* — every serious bug of the week this was written (two fail-opens,
//! found by running against a real node) was found by this layer, not by the
//! models, the conformance ties, or the unit tests. So the flow now drives
//! `uv-app` — the shared command layer the fork itself calls through `uv_call`
//! — which means this test exercises the exact code path a phone does, minus
//! the FFI marshalling.
//!
//! **What it deliberately does not test:** transports (delivery is the caller's
//! by design — see `SentPart`), bitcoind (that is `btc`'s real-node suite), and
//! the circuit's soundness (air/'s job). The chain here is `FileChain`, the
//! same backend the iOS app defaults to.

use std::path::{Path, PathBuf};

use uv_app::commands;
use uv_app::wallet::Wallet;
use uv_wallet2::chain::FileChain;
use uv_wallet2::store::NoteState;

/// One shared chain file = the "network"; three homes = three parties.
struct World {
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> World {
        let root = std::env::temp_dir().join(format!("uv-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("world root");
        World { root }
    }
    fn home(&self, who: &str) -> PathBuf {
        let h = self.root.join(who);
        std::fs::create_dir_all(&h).expect("home");
        h
    }
    fn chain_path(&self) -> PathBuf {
        self.root.join("chain.json")
    }
    /// Every command opens the shared chain fresh, exactly as the processes in
    /// the demo did — nothing is carried in memory between commands.
    fn chain(&self) -> FileChain {
        FileChain::open(self.chain_path()).expect("open shared chain")
    }
    fn mine(&self, n: u64) {
        let mut c = self.chain();
        c.mine(n);
    }
    fn wallet(&self, who: &str) -> Wallet {
        uv_app::wallet::open_or_create(&self.home(who), who, None).expect("wallet")
    }
    fn save(&self, who: &str, w: &Wallet) {
        uv_app::wallet::save(&self.home(who), who, &w.seed, &w.store, &w.log, None)
            .expect("save wallet");
    }
    /// Deliver sealed bundles into a payee's inbox — the one step that belongs
    /// to the caller, done here the way a chat layer would do it.
    fn deliver(&self, to: &str, parts: &[commands::SentPart]) {
        let inbox = uv_app::home::inbox_dir(&self.home(to));
        std::fs::create_dir_all(&inbox).expect("inbox");
        for p in parts {
            std::fs::write(inbox.join(&p.bundle_name), &p.bundle_wire).expect("deliver");
        }
    }
}

fn spendable(w: &Wallet) -> u64 {
    commands::balance(w).spendable
}

fn record_count(chain_path: &Path) -> usize {
    let st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(chain_path).expect("chain.json")).expect("json");
    st["records"].as_array().expect("records").len()
}

#[test]
fn the_whole_system_still_pays() {
    let world = World::new("main");
    let cfg = uv_air::prove::hiding_config();

    // ---- Issuance: alice mints 1000 and the genesis goes on chain ----------
    let mut alice = world.wallet("alice");
    let prepared = {
        let chain = world.chain();
        commands::prepare_issue(&mut alice, &chain, 1000).expect("prepare issue")
    };
    {
        let mut chain = world.chain();
        commands::publish_issue(&mut chain, &world.home("alice"), prepared).expect("publish issue");
    }
    world.save("alice", &alice);
    world.mine(6);

    // The anchor is the asset's public face; bob and carol import it to
    // validate anything at all.
    let anchor = uv_app::anchor::read(&world.home("alice"))
        .expect("read anchor")
        .expect("anchor exists after publish_issue");
    for who in ["bob", "carol"] {
        uv_app::anchor::import(&world.home(who), anchor.clone()).expect("import anchor");
    }

    // Issuer scans their own genesis into the store.
    {
        let chain = world.chain();
        let out = commands::scan_inbox(&world.home("alice"), "alice", &mut alice, &chain, &anchor)
            .expect("issuer self-scan");
        out.finish();
    }
    world.save("alice", &alice);
    assert_eq!(spendable(&alice), 1000, "issuer holds the genesis note");

    // ---- Hop 1: alice pays bob 300 ----------------------------------------
    let mut bob = world.wallet("bob");
    let bob_addr = commands::make_address(&world.home("bob"), "bob", &mut bob, 4, Some("alice"))
        .expect("bob address");
    world.save("bob", &bob);

    let outcome = {
        let mut chain = world.chain();
        commands::send(
            &world.home("alice"),
            "alice",
            &mut alice,
            &mut chain,
            &cfg,
            &bob_addr,
            300,
            None,
            None,
        )
        .expect("alice pays bob")
    };
    assert_eq!(outcome.rebroadcast, 0, "first spend has nothing to replay");
    assert_eq!(outcome.parts, vec![300], "one note covers 300");
    assert_eq!(outcome.sent.len(), 1);

    // ---- The sealed wire is actually sealed (demo/check_sealed.py, ported) --
    {
        let wire = &outcome.sent[0].bundle_wire;
        for leak in [
            b"amount".as_slice(),
            b"lineage",
            b"index",
            b"asset_hex",
            b"proof",
        ] {
            assert!(
                !wire.windows(leak.len()).any(|w| w == leak),
                "structure leaked through the seal: {:?}",
                String::from_utf8_lossy(leak)
            );
        }
        // Ciphertext does not compress. flate2 is not a dependency; a cheap
        // entropy proxy does the same job: all 256 byte values present and no
        // value dominating means "looks like ciphertext, not data".
        let mut hist = [0usize; 256];
        for b in wire {
            hist[*b as usize] += 1;
        }
        let distinct = hist.iter().filter(|&&n| n > 0).count();
        let max = hist.iter().copied().max().unwrap_or(0);
        assert!(
            distinct >= 250,
            "only {distinct} distinct byte values — not ciphertext"
        );
        assert!(
            max * 50 < wire.len() * 2,
            "one byte value dominates ({max} of {}) — structure is showing",
            wire.len()
        );
    }

    world.deliver("bob", &outcome.sent);
    world.mine(6);

    // ---- Bob accepts: walks the ancestry, checks settlement -----------------
    {
        let chain = world.chain();
        let out = commands::scan_inbox(&world.home("bob"), "bob", &mut bob, &chain, &anchor)
            .expect("bob scans");
        assert_eq!(
            out.accepted, 1,
            "one payment accepted, got {:?}",
            out.events
        );
        out.finish();
    }
    world.save("bob", &bob);
    assert_eq!(spendable(&bob), 300, "bob holds 300");
    assert_eq!(spendable(&alice), 700, "alice holds the change");

    // ---- Double spend: the sign-log replays, byte for byte ------------------
    // Target the note alice already spent. A conforming wallet CANNOT build a
    // second payload for it — it re-publishes the original, which the chain's
    // first-occurrence makes a no-op. Nobody is paid twice, no slot is burned.
    let spent_commitment = {
        // A note whose record is on Bitcoin but not yet confirmed-settled is
        // InFlight, not Spent — it becomes Spent only when a later scan sees it
        // settle. Either way it is no longer spendable, which is what makes a
        // second send a replay.
        let spent: Vec<_> = alice
            .store
            .iter()
            .filter(|h| matches!(h.state, NoteState::InFlight | NoteState::Spent))
            .collect();
        assert!(!spent.is_empty(), "the paid note left the spendable set");
        spent[0].note.commitment()
    };
    let records_before = record_count(&world.chain_path());
    let bob_inbox = uv_app::home::inbox_dir(&world.home("bob"));
    let inbox_before = std::fs::read_dir(&bob_inbox)
        .map(|d| d.count())
        .unwrap_or(0);

    let replay = {
        let mut chain = world.chain();
        commands::send(
            &world.home("alice"),
            "alice",
            &mut alice,
            &mut chain,
            &cfg,
            &bob_addr,
            300,
            Some(&spent_commitment),
            None,
        )
        .expect("a replay is not an error — it is the discipline working")
    };
    assert_eq!(replay.rebroadcast, 1, "the spent note replays");
    assert!(replay.sent.is_empty(), "a replay mails nothing");
    assert_eq!(
        record_count(&world.chain_path()),
        records_before,
        "first-occurrence makes the republished record a no-op"
    );
    let inbox_after = std::fs::read_dir(&bob_inbox)
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(inbox_before, inbox_after, "no new bundle was mailed");
    assert_eq!(spendable(&bob), 300, "bob is not paid twice");

    // ---- Split send: no single note covers it -------------------------------
    // Alice holds one 700 note. Paying 750 must refuse; paying via two notes is
    // [MERGE]'s stated limit. First get alice a second note: bob pays her 100.
    let alice_addr =
        commands::make_address(&world.home("alice"), "alice", &mut alice, 4, Some("bob"))
            .expect("alice address");
    world.save("alice", &alice);
    let back = {
        let mut chain = world.chain();
        commands::send(
            &world.home("bob"),
            "bob",
            &mut bob,
            &mut chain,
            &cfg,
            &alice_addr,
            100,
            None,
            None,
        )
        .expect("bob pays alice 100")
    };
    world.deliver("alice", &back.sent);
    world.mine(6);
    {
        let chain = world.chain();
        let out = commands::scan_inbox(&world.home("alice"), "alice", &mut alice, &chain, &anchor)
            .expect("alice scans");
        assert_eq!(out.accepted, 1);
        out.finish();
    }
    world.save("alice", &alice);
    assert_eq!(spendable(&alice), 800, "700 change + 100 from bob");

    // Now 750 needs both notes: two parts, two bundles, one payment.
    let mut bob2 = {
        let split = {
            let mut chain = world.chain();
            commands::send(
                &world.home("alice"),
                "alice",
                &mut alice,
                &mut chain,
                &cfg,
                &bob_addr,
                750,
                None,
                None,
            )
            .expect("alice pays 750 across two notes")
        };
        assert!(
            split.parts.len() > 1,
            "no single note covers 750; got parts {:?}",
            split.parts
        );
        assert_eq!(split.parts.iter().sum::<u64>(), 750);
        world.deliver("bob", &split.sent);
        world.mine(6);
        let chain = world.chain();
        let out = commands::scan_inbox(&world.home("bob"), "bob", &mut bob, &chain, &anchor)
            .expect("bob scans the split");
        assert_eq!(out.accepted, split.parts.len(), "every part lands");
        out.finish();
        bob
    };
    world.save("bob", &bob2);
    assert_eq!(
        spendable(&bob2),
        950,
        "200 change (paid alice 100) + 750 received"
    );
    assert_eq!(spendable(&alice), 50, "800 - 750");

    // ---- Two-hop lineage: bob pays carol with a coin that has history -------
    // Carol's accept must walk BOTH hops — the proof of alice→bob and of
    // bob→carol — and check both settled. This is the walk the design ships.
    let mut carol = world.wallet("carol");
    let carol_addr =
        commands::make_address(&world.home("carol"), "carol", &mut carol, 4, Some("bob"))
            .expect("carol address");
    world.save("carol", &carol);
    let hop2 = {
        let mut chain = world.chain();
        commands::send(
            &world.home("bob"),
            "bob",
            &mut bob2,
            &mut chain,
            &cfg,
            &carol_addr,
            100,
            None,
            None,
        )
        .expect("bob pays carol")
    };
    world.deliver("carol", &hop2.sent);
    world.mine(6);
    let carols_note = {
        let chain = world.chain();
        let out = commands::scan_inbox(&world.home("carol"), "carol", &mut carol, &chain, &anchor)
            .expect("carol scans");
        assert_eq!(
            out.accepted, 1,
            "carol validated a TWO-hop ancestry; events: {:?}",
            out.events
        );
        out.finish();
        uv_kernel2::digest::encode(
            &carol
                .store
                .iter()
                .next()
                .expect("carol holds a note")
                .note
                .commitment(),
        )
    };
    world.save("bob", &bob2);
    world.save("carol", &carol);
    assert_eq!(spendable(&carol), 100);

    // ---- Supply: counted exactly from the chain, per asset ------------------
    {
        let chain = world.chain();
        let s = commands::supply(&world.home("alice"), &chain, None);
        let total: u64 = s.assets.iter().map(|a| a.attested).sum();
        assert_eq!(
            total, 1000,
            "every coin in existence traces to the one issuance; got {s:?}"
        );
    }

    // ---- Reorg: drop the record carol's ancestry depends on -----------------
    // Exactly what local2.sh did: rewrite chain.json without hop bob→carol's
    // record. Carol reconciles and her note is QUARANTINED — not deleted, not
    // still spendable — until the record settles again.
    {
        let p = world.chain_path();
        let mut st: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&p).expect("chain.json")).expect("json");
        let records = st["records"].as_array_mut().expect("records");
        assert!(!records.is_empty());
        records.pop(); // the newest record is bob→carol's
        std::fs::write(&p, serde_json::to_vec(&st).expect("encode")).expect("rewrite chain");
    }
    {
        let chain = world.chain();
        let out = commands::reconcile(&world.home("carol"), &mut carol, &chain);
        assert!(
            out.quarantined.contains(&carols_note),
            "carol's note must be quarantined when its settlement vanishes; got {out:?}"
        );
    }
    world.save("carol", &carol);
    assert_eq!(
        spendable(&carol),
        0,
        "a quarantined note is not spendable — and not deleted"
    );
    assert!(
        carol
            .store
            .iter()
            .any(|h| uv_kernel2::digest::encode(&h.note.commitment()) == carols_note),
        "quarantine keeps the note; only its spendability is withdrawn"
    );
}
