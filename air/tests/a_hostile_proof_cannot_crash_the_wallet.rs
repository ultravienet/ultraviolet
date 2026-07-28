//! `[DESERIALIZE]`'s remaining half: a malformed proof must be *rejected*, not
//! *fatal*.
//!
//! **The gap.** `wallet2::accept` deserializes proof bytes a stranger mailed and
//! hands the result to `p3_verify`, which is not written to be safe against
//! hostile input — it indexes and unwraps its way through structures a proof
//! declares the shape of. A well-sized but malformed proof could take the
//! wallet down. Not consensus (a crash costs availability, not money), which is
//! why it outlived the soundness bugs; but "a stranger can crash your wallet by
//! mailing you a file" is a real remote denial of service, and every scan
//! re-reads the mailbox.
//!
//! **The fix** is `prove::catching_panics`, at the verifier entry points rather
//! than at `accept` — because `accept` is not the only caller (iOS and the
//! Signal path verify too) and a net that lives in one caller is a net the next
//! caller does not have.
//!
//! **What this test does, and why it is shaped oddly.** A panicking proof
//! cannot be written down as a literal; it has to be found. So this mutates an
//! honest proof's serialized bytes and replays each mutant through the real
//! entry point, asserting only ever `Err(..)` and never a process death. The
//! assertion is the *absence* of a crash, so the test fails by taking the
//! harness with it.
//!
//! **Measured, and it changed what we believe.** Random byte mutation is the
//! obvious strategy and it turned out to be the *wrong* one: 338 decoded
//! mutants, every single one rejected cleanly, not one reaching the panic
//! boundary. A flipped bit almost always breaks a Merkle path, and FRI checks
//! that long before any length field is used as an index. So the second test
//! mutates the proof **structurally** — truncating and extending the vectors
//! whose lengths the verifier trusts — which is where an out-of-bounds index
//! would actually live.
//!
//! Both are kept. The byte fuzz is the regression net; the structural fuzz is
//! the one aimed at the stated risk.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use uv_air::prove::{self, HidingTransferProof, Rejected, TransferPublics};
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};
use uv_air::wots;

fn limbs(v: u64) -> [BabyBear; 4] {
    core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
}

fn opening(perm: &p3_baby_bear::Poseidon2BabyBear<16>, tag: u32, v: u64) -> NoteOpening {
    let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
    NoteOpening {
        amount_limbs: limbs(v),
        owner_pk: wots::public_key(perm, &[tag as u8; 32]),
        anchor: sponge::hash(Domain::SpendAnchor, &nk),
        nullifier_key: nk,
        randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
    }
}

fn commitment(o: &NoteOpening, asset: &[BabyBear; 8]) -> [BabyBear; 8] {
    let mut p = Vec::new();
    p.extend_from_slice(asset);
    p.extend_from_slice(&o.amount_limbs);
    p.extend_from_slice(&o.owner_pk);
    p.extend_from_slice(&o.anchor);
    p.extend_from_slice(&o.randomness);
    sponge::hash(Domain::Note, &p)
}

fn honest() -> (TransferWitness, TransferPublics) {
    let perm = wots::permutation();
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(&perm, 41, 100);
    let outs = [opening(&perm, 42, 60), opening(&perm, 43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);

    let publics = TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    let msg = *publics.msg();
    let mut s = [BabyBear::ZERO; 16];
    s[0] = BabyBear::from_u32(1234);
    perm.permute_mut(&mut s);
    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
        sig: wots::sign(&perm, &[41u8; 32], &msg),
    };
    (witness, publics)
}

#[test]
fn mutated_proofs_are_rejected_and_never_fatal() {
    let (witness, publics) = honest();
    let cfg = prove::hiding_config();
    let good = prove::prove_transfer_hiding(&cfg, &witness, &publics);
    let bytes = bincode::serialize(&good).expect("serialize");

    // The control: the honest proof verifies. Without this the whole run could
    // be rejecting for some boring reason and prove nothing.
    prove::verify_transfer_hiding(&cfg, &good, &publics).expect("the honest proof must verify");

    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF);
    let mut decoded = 0usize;
    let mut panicked = 0usize;
    let mut rejected = 0usize;

    for round in 0..400 {
        let mut m = bytes.clone();
        // Mutate a handful of bytes. Concentrated near the front on some rounds
        // — that is where the length and shape fields live, and a length field
        // is what turns a malformed proof into an out-of-bounds index.
        let burst = 1 + (round % 4);
        for _ in 0..burst {
            let i = if round % 3 == 0 {
                rng.random_range(0..m.len().min(512))
            } else {
                rng.random_range(0..m.len())
            };
            m[i] ^= 1u8 << rng.random_range(0..8);
        }

        // Most mutants will not decode at all; that is fine and is the first
        // layer of the defence. The ones that do are the interesting ones.
        let Ok(proof) = bincode::deserialize::<HidingTransferProof>(&m) else {
            continue;
        };
        decoded += 1;

        // The real entry point. If this panics, the test process dies and the
        // suite fails — which is precisely the assertion.
        match prove::verify_transfer_hiding(&cfg, &proof, &publics) {
            Ok(()) => panic!(
                "round {round}: a mutated proof VERIFIED. This is not a \
                 robustness failure, it is a soundness failure — the mutation \
                 changed the proof and the verifier accepted it anyway."
            ),
            Err(Rejected::Panicked) => panicked += 1,
            Err(_) => rejected += 1,
        }
    }

    println!(
        "{decoded} mutants decoded: {rejected} rejected cleanly, {panicked} \
         caught by the panic boundary"
    );
    assert!(
        decoded >= 20,
        "only {decoded} mutants decoded — this run barely reached the verifier, \
         so it establishes little. Widen the mutation strategy."
    );
    // Deliberately NOT asserting `panicked > 0`. Measured: random byte mutation
    // reaches the panic boundary zero times out of ~340, because a flipped bit
    // breaks a Merkle path and FRI rejects long before a length field is used
    // as an index. Requiring a panic here would be asserting a property of the
    // fuzzer, not of the code. What this test establishes is the thing that
    // matters and nothing more: no hostile proof killed the process.
}

/// Structural mutation: break the *shapes* the verifier trusts.
///
/// This is where the `[DESERIALIZE]` risk actually lives. `opened_values`
/// carries vectors whose lengths the verifier reads and uses — a proof
/// declaring three quotient chunks where the AIR expects two, or an opening row
/// shorter than the trace is wide, is the shape that indexes out of bounds. A
/// byte-flip essentially never produces one; constructing it directly does.
///
/// **This run found something the byte fuzz could not.** Thirteen of fourteen
/// reshapes are refused with `InvalidProofShape` — upstream checks its own
/// shapes carefully, which is better news than `[DESERIALIZE]` assumed. The
/// fourteenth is not: see `Expect::Malleable`.
#[derive(Clone, Copy, PartialEq)]
enum Expect {
    /// The verifier must refuse this shape.
    Rejected,
    /// The verifier **accepts** it, and that is a known, recorded property
    /// rather than a bug we are ignoring — the field is not part of the
    /// statement, so a proof carrying it and a proof without it are two byte
    /// encodings of one valid proof.
    ///
    /// Harmless *today* for exactly the reason in spec/99 `[NO-BYTE-IDENTITY]`:
    /// proof blobs are never hashed, compared, or used as a map key, and the
    /// never-re-sign rule compares decoded `Transfer` values rather than bytes.
    /// The same argument that made bincode's trailing-byte tolerance harmless.
    ///
    /// **It stops being harmless under `[ACC]`**, which makes encodings
    /// consensus-visible. Pinned here so that if the invariant ever changes,
    /// this test is a place somebody already has to look.
    Malleable,
}

#[test]
fn structurally_malformed_proofs_are_rejected_and_never_fatal() {
    let (witness, publics) = honest();
    let cfg = prove::hiding_config();
    let good = prove::prove_transfer_hiding(&cfg, &witness, &publics);
    let bytes = bincode::serialize(&good).expect("serialize");

    let mut tried = 0usize;
    let mut panicked = 0usize;

    #[allow(clippy::type_complexity)]
    let mutations: Vec<(&str, Expect, fn(&mut HidingTransferProof))> = vec![
        ("trace_local truncated", Expect::Rejected, |p| {
            p.stark.opened_values.trace_local.pop();
        }),
        ("trace_local emptied", Expect::Rejected, |p| {
            p.stark.opened_values.trace_local.clear();
        }),
        ("trace_local doubled", Expect::Rejected, |p| {
            let extra = p.stark.opened_values.trace_local.clone();
            p.stark.opened_values.trace_local.extend(extra);
        }),
        ("trace_next truncated", Expect::Rejected, |p| {
            p.stark.opened_values.trace_next.pop();
        }),
        ("trace_next emptied", Expect::Rejected, |p| {
            p.stark.opened_values.trace_next.clear();
        }),
        ("quotient_chunks truncated", Expect::Rejected, |p| {
            p.stark.opened_values.quotient_chunks.pop();
        }),
        ("quotient_chunks emptied", Expect::Rejected, |p| {
            p.stark.opened_values.quotient_chunks.clear();
        }),
        ("quotient_chunks doubled", Expect::Rejected, |p| {
            let extra = p.stark.opened_values.quotient_chunks.clone();
            p.stark.opened_values.quotient_chunks.extend(extra);
        }),
        ("a quotient chunk truncated", Expect::Rejected, |p| {
            if let Some(c) = p.stark.opened_values.quotient_chunks.first_mut() {
                c.pop();
            }
        }),
        ("randomization dropped", Expect::Rejected, |p| {
            p.stark.opened_values.random = None;
        }),
        ("randomization emptied", Expect::Rejected, |p| {
            if let Some(r) = p.stark.opened_values.random.as_mut() {
                r.clear();
            }
        }),
        // The malleability channel. This AIR has no preprocessed trace, so an
        // honest proof carries `None` here. A proof carrying `Some(vec![])`
        // is different bytes and verifies identically.
        ("a preprocessed opening invented", Expect::Malleable, |p| {
            p.stark.opened_values.preprocessed_local = Some(vec![]);
        }),
        ("tips truncated", Expect::Rejected, |p| {
            p.tips.pop();
        }),
        ("tips doubled", Expect::Rejected, |p| {
            let extra = p.tips.clone();
            p.tips.extend(extra);
        }),
    ];

    for (name, expect, mutate) in mutations {
        let mut proof: HidingTransferProof = bincode::deserialize(&bytes).expect("round-trips");
        mutate(&mut proof);
        tried += 1;

        // A panic here takes the process down, which is the failure this test
        // exists to detect.
        let verdict = prove::verify_transfer_hiding(&cfg, &proof, &publics);
        match (&verdict, expect) {
            (Ok(()), Expect::Malleable) => {
                // Confirm it really is malleability and not a no-op: the bytes
                // must actually differ, or this row is testing nothing.
                let remade = bincode::serialize(&proof).expect("serialize");
                assert_ne!(
                    remade, bytes,
                    "{name}: expected a second encoding, got the same bytes"
                );
                println!("{name:32} -> accepted (known malleability, see Expect::Malleable)");
            }
            (Ok(()), Expect::Rejected) => panic!(
                "{name}: a structurally malformed proof VERIFIED. If this is \
                 upstream behaviour rather than a bug here, move the row to \
                 Expect::Malleable and write down why it is safe."
            ),
            (Err(Rejected::Panicked), _) => {
                panicked += 1;
                println!("{name:32} -> caught by the panic boundary");
            }
            (Err(e), Expect::Rejected) => println!("{name:32} -> rejected cleanly ({e:?})"),
            (Err(e), Expect::Malleable) => panic!(
                "{name}: expected this to be accepted as a known malleability \
                 channel, but it was refused ({e:?}). Upstream tightened — \
                 delete the row and the note about it."
            ),
        }
    }

    println!("{tried} structural mutants, {panicked} needed the panic boundary");
    assert!(tried >= 10, "the mutation table shrank; it should not have");
}

/// The boundary must not swallow honest failures into `Panicked`: an ordinary
/// wrong-statement rejection has to stay an ordinary rejection, or the error a
/// user sees stops meaning anything.
#[test]
fn an_ordinary_bad_statement_is_not_reported_as_a_panic() {
    let (witness, _publics) = honest();
    let cfg = prove::hiding_config();
    let good = prove::prove_transfer_hiding(&cfg, &witness, &honest().1);

    // Same proof, a different statement: rebuild the publics for a different
    // asset. Fields are private, so it is rebuilt from the witness rather than
    // cloned-and-poked — which is closer to what a confused caller would do.
    let wrong_asset = [BabyBear::from_u32(0xB6); 8];
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&witness.input.nullifier_key);
    nf_pre.extend_from_slice(&commitment(&witness.input, &wrong_asset));
    let other = TransferPublics::new(
        commitment(&witness.input, &wrong_asset),
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&witness.outputs[0], &wrong_asset),
        commitment(&witness.outputs[1], &wrong_asset),
        [BabyBear::ZERO; 8],
        wrong_asset,
    );
    match prove::verify_transfer_hiding(&cfg, &good, &other) {
        Err(Rejected::Stark(_)) => {}
        Err(Rejected::Panicked) => {
            panic!("a wrong statement was reported as a panic — the boundary is too wide")
        }
        verdict => panic!("a proof for a different asset must be refused: {verdict:?}"),
    }
}
