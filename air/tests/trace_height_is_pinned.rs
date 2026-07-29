//! The declared trace height is consensus data, and this pins the check on it.
//!
//! This is the regression test for the forgery an outside reviewer actually
//! built against the signature-era circuit: `p3_uni_stark` takes the trace
//! height from the *proof* — its contract is that an AIR must be sound at every
//! height — and an eight-row trace of zeros kept every money constraint gated
//! off while verifying perfectly. The fix is host-side (`prove::check_height`):
//! a proof must declare exactly the height the AIR is sound at, derived from
//! the configuration because a hiding proof legitimately declares one bit more.
//!
//! The circuit those tests guarded is deleted; the hazard is not. The
//! proof-native circuit is sound at 16 rows and nothing else, `degree_bits` is
//! still attacker-supplied bytes, and `check_height` is still the only line
//! standing between "a proof" and "a proof about the statement in hand". These
//! tests fail if it is weakened, removed, or hardcoded to the wrong constant —
//! each rejection is checked to be `WrongTraceHeight` specifically, so a
//! failure in FRI or Fiat–Shamir cannot pass as a height rejection.

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use uv_air::prove::{self, Rejected};
use uv_air::sponge::{self, Domain};
use uv_air::transfer_trace::{NoteOpening, TransferWitness};

fn limbs(v: u64) -> [BabyBear; 4] {
    core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
}

fn opening(tag: u32, v: u64) -> NoteOpening {
    let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
    NoteOpening {
        amount_limbs: limbs(v),
        anchor: sponge::hash(Domain::SpendAnchor, &nk),
        nullifier_key: nk,
        randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
    }
}

fn commitment(o: &NoteOpening, asset: &[BabyBear; 8]) -> [BabyBear; 8] {
    let mut p = Vec::new();
    p.extend_from_slice(asset);
    p.extend_from_slice(&o.amount_limbs);
    p.extend_from_slice(&o.anchor);
    p.extend_from_slice(&o.randomness);
    sponge::hash(Domain::Note, &p)
}

fn case() -> (TransferWitness, prove::TransferPublics) {
    let asset = [BabyBear::from_u32(0xA5); 8];
    let input = opening(41, 100);
    let outs = [opening(42, 60), opening(43, 40)];
    let input_commitment = commitment(&input, &asset);
    let mut nf_pre = Vec::new();
    nf_pre.extend_from_slice(&input.nullifier_key);
    nf_pre.extend_from_slice(&input_commitment);
    let publics = prove::TransferPublics::new(
        input_commitment,
        sponge::hash(Domain::Nullifier, &nf_pre),
        commitment(&outs[0], &asset),
        commitment(&outs[1], &asset),
        [BabyBear::ZERO; 8],
        asset,
    );
    let msg = *publics.msg();
    let witness = TransferWitness {
        asset,
        input,
        outputs: outs,
        msg,
    };
    (witness, publics)
}

/// A proof declaring any height but the sound one is refused before the STARK
/// verifier ever runs — in both directions, because "reject shorter" alone
/// would have missed nothing while "reject taller" alone missed the forgery.
#[test]
fn a_standard_proof_declaring_the_wrong_height_is_refused() {
    let (w, p) = case();
    let cfg = prove::config();
    let honest = prove::prove_authproto(&cfg, &w, &p);
    prove::verify_authproto(&cfg, &honest, &p).expect("the honest height verifies");

    for forged_bits in [
        honest.stark.degree_bits - 1,
        honest.stark.degree_bits + 1,
        0,
    ] {
        let mut forged = prove::prove_authproto(&cfg, &w, &p);
        forged.stark.degree_bits = forged_bits;
        match prove::verify_authproto(&cfg, &forged, &p) {
            Err(Rejected::WrongTraceHeight { expected, found }) => {
                assert_eq!(found, forged_bits, "the error reports what was declared");
                assert_eq!(
                    expected, honest.stark.degree_bits,
                    "the expected height is the derived one"
                );
            }
            other => panic!(
                "declared height {forged_bits} must be refused as WrongTraceHeight, \
                 not {other:?}"
            ),
        }
    }
}

/// The hiding path derives its expected height from the configuration — one
/// bit more than standard, for the extended domain — rather than hardcoding
/// either number. Hardcoding the standard number here once rejected every
/// honest private payment; hardcoding the hiding number would re-open the
/// forgery on the standard path.
#[test]
fn a_hiding_proof_declaring_the_wrong_height_is_refused() {
    let (w, p) = case();
    let cfg = prove::hiding_config();
    let honest = prove::prove_authproto_hiding(&cfg, &w, &p);
    prove::verify_authproto_hiding(&cfg, &honest, &p).expect("the honest height verifies");

    // In particular: `honest.stark.degree_bits - 1` is exactly the height a standard
    // proof would declare. A hiding verifier that accepts it has lost the
    // extended-domain distinction.
    for forged_bits in [
        honest.stark.degree_bits - 1,
        honest.stark.degree_bits + 1,
        0,
    ] {
        let mut forged = prove::prove_authproto_hiding(&cfg, &w, &p);
        forged.stark.degree_bits = forged_bits;
        assert!(
            matches!(
                prove::verify_authproto_hiding(&cfg, &forged, &p),
                Err(Rejected::WrongTraceHeight { .. })
            ),
            "hiding proof declaring height {forged_bits} must be refused as \
             WrongTraceHeight"
        );
    }
}
