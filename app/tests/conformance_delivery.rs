//! Model ↔ code conformance: the real scan must agree with `formal/delivery.qnt`.
//!
//! Sixth rung of the shared-source-of-truth work (spec/99 `[MODEL-CONFORMANCE]`,
//! SPEC.md §11.3), and the one claim S13 named as owed: `delivery.qnt` proved
//! that a receiver discarding a bundle on a **transient** verdict loses a
//! payment that then settles on chain, and nothing replayed that against the
//! real code. This does.
//!
//! ## The frozen counterexample, state by state
//!
//! `formal/traces/delivery_discards.itf.json` is four states long:
//!
//! | state | `bundleHeld` | `recordConfirmed` | `resendable` | what happened |
//! |---|---|---|---|---|
//! | 0 | false | false | true | nothing yet |
//! | 1 | **true** | false | true | the carrier delivered |
//! | 2 | **false** | false | **false** | scanned, verdict transient, **bundle discarded and given up on** |
//! | 3 | false | **true** | false | the record confirms — with no bundle to meet it |
//!
//! State 3 is the loss: money settled on Bitcoin that the receiver can never
//! take, because state 2 destroyed the only copy of the lineage and stopped
//! expecting the payment. This is not a hypothetical; it is the `ViewIncomplete`
//! bug this project shipped, where a wallet mid-resync deleted real payments.
//!
//! ## What is tied, and why it is the scan and not just the classifier
//!
//! `Rejected::is_permanent` is a total match over a finite enum, so asserting
//! on it alone would test a lookup table. The rule that matters is the
//! **consequence**: `app::commands::scan_inbox` calls `remove_file` when and
//! only when the verdict is permanent. So this replays the transition the model
//! forbids, through the real scan, and requires the file to survive it:
//!
//!   - **state 1 → 2 must not happen.** With a chain view that cannot answer,
//!     the real scan must report the payment as transient and **leave the
//!     bundle on disk**. The model's discard step has no counterpart in the code.
//!   - **state 3 must instead be a payment.** When the view catches up, a second
//!     real scan must **accept** the same retained bundle and raise the balance.
//!     That half is not decoration: a wallet that keeps a file it can no longer
//!     use has not fixed anything, and only running the accept proves the
//!     retained bytes were still good.
//!
//! Everything here is real — a real issuance, a real hiding STARK per hop, a
//! real sealed bundle on a real filesystem, the real `accept`. The only test
//! double is the chain view, and it is a double for the thing under test: a
//! view too narrow to answer, which is exactly what `MirrorView` returns before
//! it is caught up.
//!
//! Confirming the tie bites is `formal/traces/README.md`'s standing rule. Here
//! it is mechanical rather than remembered: flipping `ViewIncomplete` to
//! permanent in `Rejected::is_permanent` makes `the_bundle_survives_a_view_that_
//! cannot_answer` fail on a missing file, and then makes the accept half fail
//! too, because the bytes it needed are gone.

use std::path::Path;

use uv_air::poseidon2::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::issuance::Issuance;
use uv_kernel2::record::Record;
use uv_wallet2::chain::{Chain, ChainViewError, Lookup, MockChain, PublishError};
use uv_wallet2::send::{broadcast, prepare, Recipient, WalletCtx};

/// A chain view that cannot answer, then can.
///
/// Modelled on the real `uv_btc::mirror::MirrorView`, which answers
/// `Unanswerable` until its replayed index covers the tip. Writes still go
/// through: an unanswerable view publishes anyway, because a duplicate costs a
/// fee and first occurrence makes it inert, whereas skipping a publish you could
/// not check is a lost payment.
struct NarrowView<'a> {
    inner: &'a mut MockChain,
    /// When false, every lookup is `Unanswerable` — the mid-resync state.
    caught_up: bool,
}

impl Chain for NarrowView<'_> {
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
        if self.caught_up {
            self.inner.first_occurrence(nf)
        } else {
            Lookup::Unanswerable
        }
    }
    fn tip(&self) -> Result<u64, ChainViewError> {
        self.inner.tip()
    }
    fn rollback_epoch(&self) -> u64 {
        self.inner.rollback_epoch()
    }
    fn refresh(&self) {
        self.inner.refresh()
    }
    fn scan_floor(&self) -> u64 {
        // A view that cannot answer reports a floor above the chain, which is
        // how a real narrow view describes itself.
        if self.caught_up {
            self.inner.scan_floor()
        } else {
            u64::MAX
        }
    }
    fn publish(&mut self, record: &Record) -> Result<(), PublishError> {
        self.inner.publish(record)
    }
    fn publish_issuance(&mut self, issuance: &Issuance) -> Result<(), PublishError> {
        self.inner.publish_issuance(issuance)
    }
    fn issuances(&self) -> Vec<Issuance> {
        self.inner.issuances()
    }
}

/// The frozen trace's shape, asserted rather than assumed.
///
/// If the model is regenerated and the counterexample changes shape, this fails
/// here with a clear reason instead of silently replaying a different story.
/// Trace regeneration is a review event (`formal/traces/README.md`).
fn assert_trace_is_the_discard_loss() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("app/ has a parent")
        .join("formal/traces/delivery_discards.itf.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let trace: serde_json::Value = serde_json::from_str(&raw).expect("itf json");
    let states = trace["states"].as_array().expect("itf has states");

    let get = |i: usize, var: &str| -> bool {
        states[i][format!("discards::delivery::{var}")]
            .as_bool()
            .unwrap_or_else(|| panic!("state {i} has no bool {var}"))
    };

    assert_eq!(states.len(), 4, "the discard counterexample is four states");

    // State 1: delivered, not yet confirmed.
    assert!(get(1, "bundleHeld"), "state 1 holds the bundle");
    assert!(!get(1, "recordConfirmed"), "state 1 is not confirmed yet");

    // State 2: the forbidden transition — discarded AND given up on.
    assert!(!get(2, "bundleHeld"), "state 2 discarded the bundle");
    assert!(
        !get(2, "resendable"),
        "state 2 gave up on the payment; without this the discard costs only time"
    );

    // State 3: the record settles, and there is nothing left to take it with.
    assert!(get(3, "recordConfirmed"), "state 3 confirms on chain");
    assert!(
        !get(3, "bundleHeld") && !get(3, "resendable"),
        "state 3 is the loss"
    );
}

/// Alice issues, pays Bob, and Bob's bundle lands in his inbox with the record
/// on chain — the model's state 1, built for real.
struct Delivered {
    home: std::path::PathBuf,
    bundle_file: std::path::PathBuf,
    amount: u64,
}

fn deliver_a_real_payment(chain: &mut MockChain) -> Delivered {
    let home = std::env::temp_dir().join(format!(
        "uv-conf-delivery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&home);
    uv_app::home::ensure(&home).expect("home");

    // Bob first: he needs an address before anyone can pay him.
    let mut bob = uv_app::wallet::open_or_create(&home, "bob", None).expect("bob");
    let address = uv_app::commands::make_address(&home, "bob", &mut bob, 2, Some("alice"))
        .expect("bob's address");
    uv_app::wallet::save(&home, "bob", &bob.seed, &bob.store, &bob.log, None).expect("save bob");

    // Alice issues and publishes, so the lineage has a genesis on chain.
    let mut alice = uv_app::wallet::open_or_create(&home, "alice", None).expect("alice");
    let prepared = uv_app::commands::prepare_issue(&mut alice, chain, 700).expect("prepare issue");
    uv_app::commands::publish_issue(chain, &home, prepared).expect("publish issue");
    chain.mine(6);
    uv_app::wallet::save(&home, "alice", &alice.seed, &alice.store, &alice.log, None)
        .expect("save alice");

    // Alice pays Bob 300, for real: plan, prove, publish the record, seal.
    let amount = 300u64;
    let alice = uv_app::wallet::open_or_create(&home, "alice", None).expect("reopen alice");
    let plan = uv_app::commands::plan_send(&home, &alice, &address, amount, None).expect("plan");
    let anchor = uv_app::anchor::read(&home)
        .expect("anchor readable")
        .expect("anchor present");
    let uv_app::wallet::Wallet {
        seed,
        mut store,
        mut log,
    } = alice;

    let cfg = uv_air::prove::hiding_config();
    let (input, part, req) = plan
        .fresh
        .first()
        .cloned()
        .expect("one note covers 300 of 700");
    let recipient = Recipient {
        nullifier_anchor: decode(&req.nullifier_anchor_hex),
        randomness: decode(&req.randomness_hex),
    };
    let prepared_hop = prepare(
        &cfg,
        WalletCtx {
            store: &mut store,
            log: &mut log,
            seed: &seed,
        },
        &input,
        &recipient,
        Amount(part),
    )
    .expect("prepare hop");
    // `broadcast` runs its persist step between "signed" and "on Bitcoin". The
    // wallet is saved after this returns, which is the right order for a test
    // whose whole subject is durable-before-irreversible; the annotation is
    // only there because a never-failing closure leaves `E` unconstrained.
    let sent =
        broadcast(chain, prepared_hop, || Ok::<(), std::io::Error>(())).expect("publish record");
    chain.mine(6);

    let mut lineage = store
        .get(&input)
        .map(|h| h.lineage.clone())
        .unwrap_or_default();
    lineage.push(sent.hop.clone());
    let (name, wire) = uv_app::commands::seal_bundle(
        &address.scan,
        req.index,
        part,
        &anchor.asset_hex,
        lineage,
        &sent.transfer.nullifier,
    )
    .expect("seal");

    uv_app::wallet::save(&home, "alice", &seed, &store, &log, None).expect("save alice after send");

    // The carrier delivers: the sealed bundle lands in Bob's inbox.
    let inbox = uv_app::home::inbox_dir(&home);
    std::fs::create_dir_all(&inbox).expect("inbox");
    let bundle_file = inbox.join(&name);
    std::fs::write(&bundle_file, &wire).expect("deliver");
    assert!(bundle_file.exists(), "model state 1: the bundle is held");

    Delivered {
        home,
        bundle_file,
        amount: part,
    }
}

/// Little-endian 4-bytes-per-limb, the same encoding `cli::unhexd` and
/// `commands::decode_digest` use. Spelled out here rather than borrowed because
/// both of those are private, and a test that reimplements the encoding wrongly
/// would fail loudly at `prepare` rather than silently.
fn decode(hex_str: &str) -> Digest {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    let bytes = hex::decode(hex_str).expect("canonical hex digest");
    assert_eq!(bytes.len(), 32, "a digest is 8 limbs of 4 bytes");
    let mut out = [BabyBear::ZERO; 8];
    for (i, o) in out.iter_mut().enumerate() {
        let mut w = [0u8; 4];
        w.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        *o = BabyBear::from_u32(u32::from_le_bytes(w));
    }
    out
}

/// The model's forbidden transition, refused by the real scan — and then the
/// payment actually taken, which is what makes the refusal worth something.
#[test]
fn the_bundle_survives_a_view_that_cannot_answer() {
    assert_trace_is_the_discard_loss();

    let mut chain = MockChain::new();
    let d = deliver_a_real_payment(&mut chain);
    let anchor = uv_app::anchor::read(&d.home)
        .expect("anchor readable")
        .expect("anchor present");

    // ---- Model state 1 → 2: the transition that must NOT happen ----
    let mut bob = uv_app::wallet::open_or_create(&d.home, "bob", None).expect("bob");
    let before = uv_app::commands::balance(&bob).spendable;
    let narrow = NarrowView {
        inner: &mut chain,
        caught_up: false,
    };
    let outcome = uv_app::commands::scan_inbox(&d.home, "bob", &mut bob, &narrow, &anchor)
        .expect("scan runs");

    let transient = outcome
        .events
        .iter()
        .any(|e| matches!(e, uv_app::commands::ScanEvent::RejectedTransient { .. }));
    let permanent = outcome
        .events
        .iter()
        .any(|e| matches!(e, uv_app::commands::ScanEvent::RejectedPermanent { .. }));
    assert!(
        transient && !permanent,
        "a view that cannot answer is a transient verdict, not a verdict about the money; got {:?}",
        outcome.events
    );
    assert_eq!(
        outcome.accepted, 0,
        "nothing is acceptable through a blind view"
    );
    assert!(
        d.bundle_file.exists(),
        "MODEL STATE 2 REPRODUCED IN CODE: the real scan deleted a bundle on a \
         transient verdict. This is the ViewIncomplete fund loss, and \
         delivery.qnt proves it loses a settled payment."
    );
    outcome.finish();

    // ---- Model state 3, made a payment instead of a loss ----
    // The record was already on chain throughout; what changes is that our own
    // view can finally see it. In the model this is where the money is lost.
    let mut bob = uv_app::wallet::open_or_create(&d.home, "bob", None).expect("reopen bob");
    let wide = NarrowView {
        inner: &mut chain,
        caught_up: true,
    };
    let outcome =
        uv_app::commands::scan_inbox(&d.home, "bob", &mut bob, &wide, &anchor).expect("scan runs");
    assert_eq!(
        outcome.accepted, 1,
        "the retained bundle must still be spendable once the view catches up — \
         keeping a file you can no longer use is not a fix; got {:?}",
        outcome.events
    );
    let after = uv_app::commands::balance(&bob).spendable;
    assert_eq!(
        after,
        before + d.amount,
        "the payment the model loses is the payment the code takes"
    );
    outcome.finish();

    let _ = std::fs::remove_dir_all(&d.home);
}

/// The classifier, checked directly as well — because the scan above only
/// exercises the one transient variant a narrow view produces, and the model's
/// claim is about *every* transient verdict.
///
/// This is a lookup-table test and it is worth exactly what a lookup-table test
/// is worth: it fails if someone reclassifies a variant, which is the mistake
/// that actually happened.
#[test]
fn every_transient_verdict_keeps_the_bundle() {
    use uv_wallet2::accept::Rejected;

    for r in [
        Rejected::NoRecord(0),
        Rejected::InsufficientDepth(0),
        Rejected::GenesisNotIssued,
        Rejected::GenesisNotOnChain { records_seen: 0 },
        Rejected::ViewIncomplete(0),
    ] {
        assert!(
            !r.is_permanent(),
            "{r:?} is transient: no future chain state is ruled out by it, so \
             deleting the bundle destroys the only copy of a lineage that may \
             yet settle (formal/delivery.qnt)"
        );
    }
}
