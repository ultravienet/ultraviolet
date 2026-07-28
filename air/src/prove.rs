//! Proving and verifying [`crate::wots_air`].
//!
//! FRI is configured at **blowup 16 / 25 queries** (~100-bit soundness), which
//! the Phase A sweep found to be the best point: prove time had ~50× headroom
//! against the gate, so spending it took the proof from 407 KB to 138 KB
//! (spec/04).
//!
//! Two configurations, because they answer different questions:
//! - [`prove`] / [`verify`] — the standard STARK.
//! - [`prove_hiding`] / [`verify_hiding`] — blinded commitments and a randomized
//!   FRI, i.e. genuinely zero-knowledge. SP1's raw proofs have no hiding at any
//!   price, so this is a property the rewrite *adds*; measured at 4.2× prove
//!   time and 1.36× proof size.

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_commit::Pcs as PcsTrait;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{
    prove as p3_prove, verify as p3_verify, Proof, StarkConfig, StarkGenericConfig,
    VerificationError,
};

/// The verifier's error type, spelled out because it is parameterised by the
/// commitment scheme's own error.
pub type VerifyError<C> = VerificationError<
    <<C as p3_uni_stark::StarkGenericConfig>::Pcs as PcsTrait<
        <C as p3_uni_stark::StarkGenericConfig>::Challenge,
        <C as p3_uni_stark::StarkGenericConfig>::Challenger,
    >>::Error,
>;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::trace;
use crate::transfer_air::TransferAir;
use crate::wots::{self, CHAINS};
use crate::wots_air::{WotsAir, NUM_PUBLIC_VALUES};

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type Dft = p3_dft::Radix2DitParallel<Val>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

type ValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

type HidingValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    StdRng,
    4,
    4,
>;
type HidingChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingValMmcs>;
type HidingPcs = HidingFriPcs<Val, Dft, HidingValMmcs, HidingChallengeMmcs, StdRng>;
pub type HidingConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

/// A configuration this crate vouches for.
///
/// **Why a wrapper and not just a type alias.** The FRI parameters — blowup,
/// query count, proof-of-work bits — are exactly as load-bearing as the trace
/// height, and the trace height is what an adversarial reader forged a payment
/// through earlier today. `StarkConfig::new`, `TwoAdicFriPcs::new` and
/// `FriParameters` are all public upstream types, so before this existed any
/// caller could build a configuration with blowup 1, one query and zero
/// proof-of-work bits — on the order of two bits of soundness — and hand it to
/// [`verify_transfer`], which would verify against it without complaint.
///
/// Nothing in this repository ever did that. That is precisely the problem: it
/// was protected by convention, and so was the height. There is deliberately no
/// public constructor, so the only configurations that reach a consensus entry
/// point are [`config`] and [`hiding_config`], and a weakened one is a compile
/// error rather than a silent collapse.
pub struct Vouched<C>(C);

impl<C> Vouched<C> {
    /// Read-only access, for the prover and the raw verifier. Handing the inner
    /// configuration out is safe; being able to *construct* one is not.
    pub fn inner(&self) -> &C {
        &self.0
    }
}

/// Soundness is roughly `queries × log_blowup` bits. These hold ~100 bits at the
/// smallest proof the Phase A sweep found.
const LOG_BLOWUP: usize = 4;
const NUM_QUERIES: usize = 25;

fn fri_params<M>(mmcs: M) -> FriParameters<M> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs,
    }
}

fn hashers() -> (ByteHash, U64Hash) {
    (ByteHash {}, U64Hash::new(KeccakF {}))
}

/// What the challenger is seeded with.
///
/// Both challengers used to start from an *empty* vector, so nothing bound a
/// proof to this protocol at all. Upstream flags the same gap in its own
/// source: *"Might be best practice to include other instance data here in the
/// transcript... This protects against transcript collisions between distinct
/// instances."*
///
/// **What this fixes and what it does not.** It binds the protocol and a
/// version, so a proof cannot be carried in from another system built on the
/// same primitives, and a future format change can be separated cleanly.
///
/// It does **not** separate the two AIRs from each other — one configuration
/// serves both. That separation rests on two properties, and it is worth
/// writing down which, because both used to be incidental and only one still
/// is:
///
/// - **Trace width**, 392 against 457, checked by `p3_uni_stark::verify`
///   against `A::width(air)` and bound to the commitment through the Merkle
///   leaf. Enforced, soundly, by the library.
/// - **Public-value count**, 603 against 659, now asserted at both entry points
///   rather than `debug_assert`ed. This matters more than it looks: a transfer
///   statement's public values *begin with* exactly the 603 elements of a
///   complete signature statement, so length is what stops the prefix being
///   reinterpreted.
///
/// A third AIR sharing both a width and a public-value count with an existing
/// one would need its own tag here. Nothing warns you; this comment is the
/// warning.
fn transcript_seed() -> Vec<u8> {
    b"ultraviolet/air/v1".to_vec()
}

/// Standard (non-hiding) configuration.
pub fn config() -> Vouched<Config> {
    let (byte_hash, u64_hash) = hashers();
    let val_mmcs = ValMmcs::new(FieldHash::new(u64_hash), Compress::new(u64_hash));
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params(challenge_mmcs));
    Vouched(Config::new(
        pcs,
        Challenger::from_hasher(transcript_seed(), byte_hash),
    ))
}

/// Zero-knowledge configuration.
///
/// **The blinding is drawn from the operating system on every call, never from a
/// fixed seed, and it comes from a cryptographic generator.** Both of those are
/// load-bearing and both were wrong here once.
///
/// FRI opens trace cells at its query positions, and those cells are witness
/// data — amounts, keys, randomness. The blinding masks them, so the mask has to
/// be secret from everyone but the prover. An earlier version seeded it from a
/// compile-time constant, reasoning that the blinding "only needs to be
/// unpredictable to the verifier". That is wrong twice over: a constant in
/// open-source code is unpredictable to nobody, and a proof built from a fixed
/// seed is a deterministic function of its witness — proving the same payment
/// twice gave byte-identical proofs, which is a fingerprint of the witness and
/// not zero-knowledge under any definition.
///
/// `StdRng` rather than `SmallRng` for the same reason: `SmallRng` is documented
/// as unsuitable for cryptography, and this is cryptography.
///
/// Soundness never depended on this — a verifier checks the same constraints
/// either way, so no money was at risk. What was at risk is the confidentiality
/// the hiding configuration exists to buy.
///
/// There is deliberately no seeded variant, not even for tests: a reproducible
/// zero-knowledge proof is a contradiction, and offering one invites a caller to
/// reintroduce exactly this bug.
pub fn hiding_config() -> Vouched<HidingConfig> {
    let (byte_hash, u64_hash) = hashers();
    let val_mmcs = HidingValMmcs::new(
        FieldHash::new(u64_hash),
        Compress::new(u64_hash),
        StdRng::from_os_rng(),
    );
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let pcs = HidingPcs::new(
        Dft::default(),
        val_mmcs,
        fri_params(challenge_mmcs),
        4,
        StdRng::from_os_rng(),
    );
    Vouched(HidingConfig::new(
        pcs,
        Challenger::from_hasher(transcript_seed(), byte_hash),
    ))
}

/// A WOTS+ proof: the STARK plus the chain tips it binds.
///
/// The tips ride with the proof because the verifier needs them twice: as
/// public values (constraint 17 pins each chain's endpoint to them) and as the
/// preimage for the host-side `compress(tips) == pk` check. They are not
/// secret — they are exactly what a plain WOTS+ verifier recomputes from the
/// signature. `Vec` rather than `[Digest; CHAINS]` only for serde's sake; the
/// length is checked before anything else.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct WotsProof {
    pub stark: Proof<Config>,
    pub tips: Vec<wots::Digest>,
}

/// [`WotsProof`], hiding configuration.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HidingWotsProof {
    pub stark: Proof<HidingConfig>,
    pub tips: Vec<wots::Digest>,
}

/// Why a proof was rejected.
#[derive(Debug)]
pub enum Rejected<E> {
    /// The proof does not carry exactly one tip per chain.
    MalformedTips,
    /// `compress(tips)` is not the public key being verified against.
    PublicKeyMismatch,
    /// The STARK failed against the verifier-derived public values.
    Stark(E),
    /// The verifier panicked on this proof rather than rejecting it.
    ///
    /// `p3_verify` is not written to be hostile-input-safe: a well-sized but
    /// malformed `Proof` can index out of bounds or unwrap a `None` deep inside
    /// FRI. Reached from `wallet2::accept`, which deserializes proof bytes a
    /// stranger mailed, that is a remote crash — availability, not money
    /// (spec/99 `[DESERIALIZE]`), which is why it sat open as long as it did.
    ///
    /// Catching the unwind converts it into an ordinary rejection. It does not
    /// make the verifier safe; it makes a wallet survive meeting an unsafe one.
    /// An abort-on-panic profile would defeat this, and the repository does not
    /// set one.
    Panicked,
    /// The proof declares a trace height this AIR is not sound at.
    ///
    /// `p3_uni_stark` takes the trace height from the proof and never pins it,
    /// so the height is prover-chosen unless the caller checks. Both AIRs here
    /// are sound only at their designed height: shorter, and the position
    /// counter never reaches the end of a chain, so `is_last` never fires, the
    /// sponge section never begins, and every constraint gated on either of
    /// those silently does nothing. The height is part of the statement.
    WrongTraceHeight { expected: usize, found: usize },
}

/// Run a verification, converting a panic into [`Rejected::Panicked`].
///
/// Every verifier entry point goes through this. The boundary is here rather
/// than at `wallet2::accept` deliberately: `accept` is not the only caller —
/// the iOS FFI and the Signal path verify too — and a safety net that lives in
/// one caller is a safety net the next caller does not have. Same argument that
/// moved the issuance-floor check into `accept`.
///
/// Takes a closure rather than the pieces, because `p3_verify`'s bounds are
/// long enough that restating them here would be its own maintenance hazard.
///
/// `AssertUnwindSafe` is honest here rather than a shortcut: everything the
/// closure touches is borrowed immutably and read-only, so there is no state a
/// partial verification could leave inconsistent.
fn catching_panics<E>(f: impl FnOnce() -> Result<(), E>) -> Result<(), Rejected<E>> {
    // The hook is silenced only for the duration of the call. A verifier panic
    // is expected input-handling here, and dumping a backtrace for every piece
    // of junk mail would be its own denial of service on the terminal.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    match outcome {
        Ok(r) => r.map_err(Rejected::Stark),
        Err(_) => Err(Rejected::Panicked),
    }
}

/// Trace height of the signature AIR, as a power of two.
pub const WOTS_DEGREE_BITS: usize = (crate::wots::CHAINS * crate::wots_air::ROWS_PER_CHAIN)
    .next_power_of_two()
    .trailing_zeros() as usize;

/// Trace height of the transfer AIR, as a power of two.
pub const TRANSFER_DEGREE_BITS: usize = (crate::wots_air::CHAIN_ROWS
    + crate::transfer_air::SPONGE_ROWS)
    .next_power_of_two()
    .trailing_zeros() as usize;

/// Reject any proof that does not declare exactly the height its AIR is sound at.
///
/// This is a consensus rule, and the third of them — the other two being that
/// public values are built by the verifier and that the owner key is *defined*
/// as `compress(tips)`. It is the easiest of the three to lose, because unlike
/// the other two nothing in the AIR hints that it exists. **A recursive verifier
/// must reproduce all three.** Without this one a prover picks a height where
/// the interesting constraints are gated off and proves whatever it likes.
///
/// The expected value is derived, not written down. A zero-knowledge
/// configuration proves over an *extended* domain — `p3_uni_stark` sets
/// `degree_bits = log_degree + config.is_zk()` — so a hiding proof legitimately
/// declares one more bit than a standard one. Hardcoding the standard number
/// here rejects every honest payment, which is a mistake this code has already
/// made once.
fn check_height<SC, E>(config: &SC, found: usize, trace_bits: usize) -> Result<(), Rejected<E>>
where
    SC: StarkGenericConfig,
{
    let expected = trace_bits + config.is_zk();
    if found != expected {
        return Err(Rejected::WrongTraceHeight { expected, found });
    }
    Ok(())
}

/// The verifier's public values: `digits(msg) ++ tips`, in the AIR's layout.
///
/// Always constructed by the verifier from the message it is deciding to
/// accept — never taken from the prover — which is what makes constraint 16's
/// digits *the message's* digits. The prover calls this too, but only so that
/// its transcript matches the verifier's.
fn public_values(msg: &wots::Digest, tips: &[wots::Digest; CHAINS]) -> Vec<Val> {
    let mut pv = Vec::with_capacity(NUM_PUBLIC_VALUES);
    pv.extend(
        wots::digits(msg)
            .iter()
            .map(|&d| BabyBear::from_u32(u32::from(d))),
    );
    for tip in tips {
        pv.extend_from_slice(tip);
    }
    // Not `debug_assert`: that compiles out of release, and a mismatch panics
    // inside the constraint folder rather than rejecting. The public-value
    // length and layout are part of the statement — a fourth wrapper obligation
    // beside verifier-built values, the definitional owner key, and the height.
    assert_eq!(
        pv.len(),
        NUM_PUBLIC_VALUES,
        "public-value layout changed; this is part of the statement"
    );
    pv
}

/// Prove one WOTS+ verification: `sig` is a valid signature on `msg`.
pub fn prove(config: &Vouched<Config>, msg: &wots::Digest, sig: &wots::Signature) -> WotsProof {
    let trace = trace::generate(msg, sig);
    let tips = trace::tips_from_trace(&trace);
    let pv = public_values(msg, &tips);
    let stark = p3_prove(config.inner(), &WotsAir::default(), trace, &pv);
    WotsProof {
        stark,
        tips: tips.to_vec(),
    }
}

/// Verify a [`WotsProof`] against a message and a public key.
///
/// This wrapper is the **entire** verification procedure and the only exported
/// one. Its two host-side checks are consensus rules, not conveniences: the
/// public values must be built from the message being accepted, and the tips
/// must compress to the key. The raw STARK verifier with any other public
/// values proves nothing about `msg` or `pk` (see [`crate::wots_air`] docs).
pub fn verify(
    config: &Vouched<Config>,
    proof: &WotsProof,
    msg: &wots::Digest,
    pk: &wots::Digest,
) -> Result<(), Rejected<VerifyError<Config>>> {
    let tips: [wots::Digest; CHAINS] = proof
        .tips
        .as_slice()
        .try_into()
        .map_err(|_| Rejected::MalformedTips)?;
    check_height(config.inner(), proof.stark.degree_bits, WOTS_DEGREE_BITS)?;
    let perm = wots::permutation();
    if wots::compress(&perm, &tips) != *pk {
        return Err(Rejected::PublicKeyMismatch);
    }
    let pv = public_values(msg, &tips);
    catching_panics(|| p3_verify(config.inner(), &WotsAir::default(), &proof.stark, &pv))
}

/// [`prove`], zero-knowledge configuration.
pub fn prove_hiding(
    config: &Vouched<HidingConfig>,
    msg: &wots::Digest,
    sig: &wots::Signature,
) -> HidingWotsProof {
    let trace = trace::generate(msg, sig);
    let tips = trace::tips_from_trace(&trace);
    let pv = public_values(msg, &tips);
    let stark = p3_prove(config.inner(), &WotsAir::default(), trace, &pv);
    HidingWotsProof {
        stark,
        tips: tips.to_vec(),
    }
}

/// [`verify`], zero-knowledge configuration. Same wrapper obligations.
pub fn verify_hiding(
    config: &Vouched<HidingConfig>,
    proof: &HidingWotsProof,
    msg: &wots::Digest,
    pk: &wots::Digest,
) -> Result<(), Rejected<VerifyError<HidingConfig>>> {
    let tips: [wots::Digest; CHAINS] = proof
        .tips
        .as_slice()
        .try_into()
        .map_err(|_| Rejected::MalformedTips)?;
    check_height(config.inner(), proof.stark.degree_bits, WOTS_DEGREE_BITS)?;
    let perm = wots::permutation();
    if wots::compress(&perm, &tips) != *pk {
        return Err(Rejected::PublicKeyMismatch);
    }
    let pv = public_values(msg, &tips);
    catching_panics(|| p3_verify(config.inner(), &WotsAir::default(), &proof.stark, &pv))
}

// ---- The transfer circuit ----

/// A transfer proof: the STARK plus the chain tips, as in [`WotsProof`].
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransferProof {
    pub stark: Proof<Config>,
    pub tips: Vec<wots::Digest>,
}

/// [`TransferProof`], hiding configuration — the configuration that actually
/// hides the amounts and keys the transfer witness contains.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HidingTransferProof {
    pub stark: Proof<HidingConfig>,
    pub tips: Vec<wots::Digest>,
}

/// The public statement of one hop, as raw digests.
///
/// `uv-kernel2`'s wrapper derives this from a `Transfer` — including `msg` as
/// the transfer's own bundle hash — and is the consensus entry point. Calling
/// [`verify_transfer`] with a `msg` that is NOT the bundle hash of the
/// transfer being validated proves nothing about that transfer.
#[derive(Clone)]
pub struct TransferPublics {
    input_commitment: wots::Digest,
    nullifier: wots::Digest,
    out0: wots::Digest,
    out1: wots::Digest,
    prev_history: wots::Digest,
    asset: wots::Digest,
    /// The bundle hash — the WOTS+ message. **Derived, never supplied.**
    msg: wots::Digest,
}

/// The bundle hash: what a record commits to, and the exact message the input
/// note's one-time key signs.
///
/// Defined here, beside the sponge, so there is exactly one definition.
/// `kernel2::transfer::Transfer::bundle_hash` delegates to it. Two definitions
/// of the message a signature covers is a way for the signed thing and the
/// validated thing to drift apart.
pub fn bundle_hash(
    input_commitment: &wots::Digest,
    nullifier: &wots::Digest,
    prev_history: &wots::Digest,
    outputs: &[wots::Digest],
) -> wots::Digest {
    let mut e = Vec::with_capacity(8 * (3 + outputs.len()));
    e.extend_from_slice(input_commitment);
    e.extend_from_slice(nullifier);
    e.extend_from_slice(prev_history);
    for out in outputs {
        e.extend_from_slice(out);
    }
    crate::sponge::hash(crate::sponge::Domain::Bundle, &e)
}

impl TransferPublics {
    /// The only way to build a transfer statement.
    ///
    /// **`msg` is derived here, not accepted.** The fields are private for one
    /// reason: the wrapper's first consensus obligation is that public values
    /// are built by the verifier from the transfer it is validating, and a
    /// struct with public fields lets a caller supply a `msg` belonging to some
    /// other transfer — at which point the proof binds nothing. Making the
    /// message a function of the other fields turns that obligation from a rule
    /// someone has to remember into one the type enforces.
    pub fn new(
        input_commitment: wots::Digest,
        nullifier: wots::Digest,
        out0: wots::Digest,
        out1: wots::Digest,
        prev_history: wots::Digest,
        asset: wots::Digest,
    ) -> Self {
        let msg = bundle_hash(&input_commitment, &nullifier, &prev_history, &[out0, out1]);
        Self {
            input_commitment,
            nullifier,
            out0,
            out1,
            prev_history,
            asset,
            msg,
        }
    }

    /// The bundle hash this statement is bound to.
    pub fn msg(&self) -> &wots::Digest {
        &self.msg
    }

    /// This statement flattened into the AIR's public-value layout.
    ///
    /// Public so that adversarial tests can drive the raw prover without
    /// keeping their own copy of the encoding — a copy would drift, and a
    /// drifted copy makes an attack test quietly stop testing the attack.
    /// Handing this out is safe in a way that public *fields* were not: a
    /// `TransferPublics` can only be built by [`Self::new`], which derives the
    /// message rather than accepting one.
    pub fn to_public_values(&self, tips: &[wots::Digest; CHAINS]) -> Vec<Val> {
        transfer_public_values(self, tips)
    }
}

/// Public values for the transfer AIR. The owner key is *defined* as
/// `compress(tips)` — the wrapper's key check is definitional rather than a
/// comparison, so it cannot be skipped or botched.
fn transfer_public_values(publics: &TransferPublics, tips: &[wots::Digest; CHAINS]) -> Vec<Val> {
    let perm = wots::permutation();
    let owner_pk = wots::compress(&perm, tips);
    let mut pv = public_values(&publics.msg, tips);
    for part in [
        &publics.input_commitment,
        &publics.nullifier,
        &publics.out0,
        &publics.out1,
        &publics.prev_history,
        &publics.asset,
        &owner_pk,
    ] {
        pv.extend_from_slice(part.as_slice());
    }
    assert_eq!(
        pv.len(),
        crate::transfer_air::NUM_PUBLIC_VALUES,
        "public-value layout changed; this is part of the statement"
    );
    pv
}

/// Prove one hop. The witness must already be internally consistent (the
/// kernel2 wrapper builds it from real notes); an inconsistent witness fails
/// in `check_constraints` (debug) or yields an unverifiable proof.
pub fn prove_transfer(
    config: &Vouched<Config>,
    witness: &crate::transfer_trace::TransferWitness,
    publics: &TransferPublics,
) -> TransferProof {
    let trace = crate::transfer_trace::generate(witness);
    let tips = trace::tips_from_trace(&trace);
    let pv = transfer_public_values(publics, &tips);
    let stark = p3_prove(config.inner(), &TransferAir::default(), trace, &pv);
    TransferProof {
        stark,
        tips: tips.to_vec(),
    }
}

/// Verify one hop against its public statement.
///
/// Kernel2's `transfer_prove::verify` is the consensus entry point: it is the
/// layer that derives `publics` — bundle hash included — from the transfer
/// being validated. This function trusts `publics` and completes the
/// STARK + wrapper obligations (verifier-built pv; owner key defined from the
/// proof's tips).
pub fn verify_transfer(
    config: &Vouched<Config>,
    proof: &TransferProof,
    publics: &TransferPublics,
) -> Result<(), Rejected<VerifyError<Config>>> {
    let tips: [wots::Digest; CHAINS] = proof
        .tips
        .as_slice()
        .try_into()
        .map_err(|_| Rejected::MalformedTips)?;
    check_height(
        config.inner(),
        proof.stark.degree_bits,
        TRANSFER_DEGREE_BITS,
    )?;
    let pv = transfer_public_values(publics, &tips);
    catching_panics(|| p3_verify(config.inner(), &TransferAir::default(), &proof.stark, &pv))
}

/// [`prove_transfer`], zero-knowledge configuration.
pub fn prove_transfer_hiding(
    config: &Vouched<HidingConfig>,
    witness: &crate::transfer_trace::TransferWitness,
    publics: &TransferPublics,
) -> HidingTransferProof {
    let trace = crate::transfer_trace::generate(witness);
    let tips = trace::tips_from_trace(&trace);
    let pv = transfer_public_values(publics, &tips);
    let stark = p3_prove(config.inner(), &TransferAir::default(), trace, &pv);
    HidingTransferProof {
        stark,
        tips: tips.to_vec(),
    }
}

/// [`verify_transfer`], zero-knowledge configuration.
pub fn verify_transfer_hiding(
    config: &Vouched<HidingConfig>,
    proof: &HidingTransferProof,
    publics: &TransferPublics,
) -> Result<(), Rejected<VerifyError<HidingConfig>>> {
    let tips: [wots::Digest; CHAINS] = proof
        .tips
        .as_slice()
        .try_into()
        .map_err(|_| Rejected::MalformedTips)?;
    check_height(
        config.inner(),
        proof.stark.degree_bits,
        TRANSFER_DEGREE_BITS,
    )?;
    let pv = transfer_public_values(publics, &tips);
    catching_panics(|| p3_verify(config.inner(), &TransferAir::default(), &proof.stark, &pv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_symmetric::Permutation;

    fn msg_of(tag: u32) -> wots::Digest {
        let perm = wots::permutation();
        let mut s = [BabyBear::ZERO; wots::WIDTH];
        s[0] = BabyBear::from_u32(tag);
        perm.permute_mut(&mut s);
        let mut d = [BabyBear::ZERO; wots::N];
        d.copy_from_slice(&s[..wots::N]);
        d
    }

    /// The circuit proves and verifies an honest signature's verification.
    ///
    /// This is the load-bearing test: it means the vendored Poseidon2 constraints
    /// and our chaining constraints together accept the witness that
    /// `wots::verify` accepts. A failure here means host and circuit compute
    /// different functions.
    #[test]
    fn an_honest_signature_proves_and_verifies() {
        let perm = wots::permutation();
        let seed = [31u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(11);
        let sig = wots::sign(&perm, &seed, &msg);
        assert!(wots::verify(&perm, &pk, &msg, &sig));

        let cfg = config();
        let proof = prove(&cfg, &msg, &sig);
        verify(&cfg, &proof, &msg, &pk).expect("the circuit must accept an honest witness");
    }

    /// A witness whose chain advance is tampered with must be rejected by the
    /// constraints — not merely produce different tips.
    #[test]
    fn a_tampered_trace_is_rejected_by_the_constraints() {
        let perm = wots::permutation();
        let seed = [32u8; 32];
        let msg = msg_of(12);
        let sig = wots::sign(&perm, &seed, &msg);

        let mut t = trace::generate(&msg, &sig);
        // Corrupt one chain_out cell: the selector constraint
        // `chain_out = sel*perm_out + (1-sel)*chain_in` no longer holds.
        let cell = crate::wots_air::CHAIN_OUT;
        t.values[cell] += BabyBear::ONE;
        must_not_verify(t, &msg, "a tampered chain advance");
    }

    /// Helper: prove must either fail or produce a proof that does not verify.
    /// Silently verifying a false statement is the one unacceptable outcome.
    ///
    /// The public values are built from the trace's *own* tips and the given
    /// message — the most charitable pv the prover could hope for — so a
    /// rejection here is the constraints' doing, not a transcript technicality.
    fn must_not_verify(
        t: p3_matrix::dense::RowMajorMatrix<BabyBear>,
        msg: &wots::Digest,
        what: &str,
    ) {
        let cfg = config();
        let tips = trace::tips_from_trace(&t);
        let pv = public_values(msg, &tips);
        let air = WotsAir::default();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p3_prove(cfg.inner(), &air, t, &pv)
        })) {
            Err(_) => {}
            Ok(proof) => assert!(
                p3_verify(cfg.inner(), &air, &proof, &pv).is_err(),
                "{what} must never verify"
            ),
        }
    }

    fn honest_trace(
        tag: u32,
        seed_byte: u8,
    ) -> (p3_matrix::dense::RowMajorMatrix<BabyBear>, wots::Digest) {
        let perm = wots::permutation();
        let seed = [seed_byte; 32];
        let msg = msg_of(tag);
        let sig = wots::sign(&perm, &seed, &msg);
        (trace::generate(&msg, &sig), msg)
    }

    /// Constraint 10: selectors must be non-increasing within a chain. Moving an
    /// active step later — same count, different position — reaches a different
    /// tip, so scattering must be refused.
    #[test]
    fn scattering_the_walk_within_a_chain_is_rejected() {
        use crate::wots_air::{NUM_COLS, SEL};
        let (mut t, msg) = honest_trace(41, 51);
        // Find a chain row where sel drops 1 -> 0, then swap the two.
        let mut swapped = false;
        for row in 0..(crate::wots_air::CHAIN_ROWS - 1) {
            let a = row * NUM_COLS + SEL;
            let b = (row + 1) * NUM_COLS + SEL;
            if t.values[a] == BabyBear::ONE && t.values[b] == BabyBear::ZERO {
                t.values[a] = BabyBear::ZERO;
                t.values[b] = BabyBear::ONE;
                swapped = true;
                break;
            }
        }
        assert!(swapped, "test needs a 1->0 selector boundary");
        must_not_verify(t, &msg, "a scattered selector pattern");
    }

    /// Constraints 7 and 16: the walk length must match the digit, and the digit
    /// must match the public value. Claiming a different digit than the walk
    /// performed must be refused.
    #[test]
    fn claiming_a_digit_the_walk_does_not_match_is_rejected() {
        use crate::wots_air::{BITS, DIGIT, NUM_COLS};
        let (mut t, msg) = honest_trace(42, 52);
        // Bump chain 0's digit (and its bits, so the range check still passes)
        // without changing how many steps were walked.
        for s in 0..crate::wots_air::ROWS_PER_CHAIN {
            let base = s * NUM_COLS;
            let d = t.values[base + DIGIT];
            let new_d = d + BabyBear::ONE;
            t.values[base + DIGIT] = new_d;
            let raw = new_d.as_canonical_u32();
            for k in 0..crate::wots::LOG_W {
                t.values[base + BITS + k] = BabyBear::from_bool((raw >> k) & 1 == 1);
            }
        }
        must_not_verify(t, &msg, "a digit inconsistent with the walk length");
    }

    /// Constraint 5: digits are range-checked by boolean bits. A non-boolean bit
    /// must be refused, since otherwise `digit` escapes 0..16.
    #[test]
    fn a_non_boolean_digit_bit_is_rejected() {
        use crate::wots_air::BITS;
        let (mut t, msg) = honest_trace(43, 53);
        t.values[BITS] = BabyBear::from_u32(2);
        must_not_verify(t, &msg, "a non-boolean digit bit");
    }

    // ---- The binding tests: unwritable before public values existed ----

    /// A proof made for one message must not verify against another. This was
    /// THE forgery gap: without public values, nothing tied the proof to any
    /// message at all.
    #[test]
    fn a_proof_does_not_verify_against_a_different_message() {
        let perm = wots::permutation();
        let seed = [61u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(21);
        let other = msg_of(22);
        assert_ne!(wots::digits(&msg), wots::digits(&other));
        let sig = wots::sign(&perm, &seed, &msg);

        let cfg = config();
        let proof = prove(&cfg, &msg, &sig);
        verify(&cfg, &proof, &msg, &pk).expect("sanity: honest verify");
        assert!(
            matches!(verify(&cfg, &proof, &other, &pk), Err(Rejected::Stark(_))),
            "a different message must be rejected by the AIR, not merely differ"
        );
    }

    /// A proof must not verify against a different public key.
    #[test]
    fn a_proof_does_not_verify_against_a_different_key() {
        let perm = wots::permutation();
        let seed = [62u8; 32];
        let other_seed = [63u8; 32];
        let msg = msg_of(23);
        let sig = wots::sign(&perm, &seed, &msg);
        let other_pk = wots::public_key(&perm, &other_seed);

        let cfg = config();
        let proof = prove(&cfg, &msg, &sig);
        assert!(
            matches!(
                verify(&cfg, &proof, &msg, &other_pk),
                Err(Rejected::PublicKeyMismatch)
            ),
            "a foreign key must fail the compress check"
        );
    }

    /// The compress-check-evading forgery: tamper a tip AND verify against the
    /// key that compresses from the tampered tips, so the host-side check
    /// passes. Constraint 17 must reject — this is the test that proves the
    /// pk binding lives in the AIR, not just in the wrapper.
    #[test]
    fn tampered_tips_that_satisfy_the_key_check_are_still_rejected() {
        let perm = wots::permutation();
        let seed = [64u8; 32];
        let msg = msg_of(24);
        let sig = wots::sign(&perm, &seed, &msg);

        let cfg = config();
        let mut proof = prove(&cfg, &msg, &sig);
        proof.tips[9][0] += BabyBear::ONE;
        let tampered: [wots::Digest; CHAINS] = proof.tips.as_slice().try_into().unwrap();
        let complicit_pk = wots::compress(&perm, &tampered);

        match verify(&cfg, &proof, &msg, &complicit_pk) {
            Err(Rejected::Stark(_)) => {}
            Err(other) => panic!("must fail in the AIR, not the wrapper: {other:?}"),
            Ok(()) => panic!("a tampered tip with a complicit key must never verify"),
        }
    }

    /// An internally consistent trace for a DIFFERENT message's digits must be
    /// rejected when the public values carry the claimed message's digits.
    /// Before constraint 16 this was exactly the available forgery: every
    /// in-trace constraint held, and nothing compared digits to anything.
    #[test]
    fn a_digit_vector_for_a_different_message_is_rejected() {
        let perm = wots::permutation();
        let seed = [65u8; 32];
        let claimed = msg_of(25);
        let actual = msg_of(26);
        assert_ne!(wots::digits(&claimed), wots::digits(&actual));
        let sig = wots::sign(&perm, &seed, &actual);

        // The trace honestly verifies `actual`'s signature...
        let t = trace::generate(&actual, &sig);
        // ...but the verifier builds public values for `claimed`.
        must_not_verify(t, &claimed, "digits for a different message");
    }

    /// Constraint 14: a chain boundary cannot be moved. Before POS/PINV pinned
    /// it, `is_last` was merely boolean — a prover could shift boundaries and
    /// re-map chains onto the wrong public digits and tips.
    #[test]
    fn a_shifted_chain_boundary_is_rejected() {
        use crate::wots_air::{IS_LAST, NUM_COLS};
        let (mut t, msg) = honest_trace(44, 54);
        // Claim a boundary at row 3 (pos = 3, not W-2).
        t.values[3 * NUM_COLS + IS_LAST] = BabyBear::ONE;
        must_not_verify(t, &msg, "a boundary at the wrong position");

        let (mut t, msg) = honest_trace(45, 55);
        // Erase the real boundary at the end of chain 0 (pos = W-2).
        t.values[(crate::wots_air::ROWS_PER_CHAIN - 1) * NUM_COLS + IS_LAST] = BabyBear::ZERO;
        must_not_verify(t, &msg, "an erased boundary");
    }

    /// Constraint 15: the one-hot register is fully determined; re-labelling a
    /// row as belonging to a different chain must be rejected, else a prover
    /// pairs chain c's walk with chain d's public digit and tip.
    #[test]
    fn a_tampered_one_hot_register_is_rejected() {
        use crate::wots_air::{NUM_COLS, OH};
        let (mut t, msg) = honest_trace(46, 56);
        // Row 20 belongs to chain 1; claim it belongs to chain 2.
        let base = 20 * NUM_COLS;
        t.values[base + OH + 1] = BabyBear::ZERO;
        t.values[base + OH + 2] = BabyBear::ONE;
        must_not_verify(t, &msg, "a re-labelled chain index");
    }

    /// The permutation layout's `export` flag was the one column in the whole
    /// trace that nothing constrained — 1,024 free field elements a prover
    /// could set to anything. Upstream never reads it; we pin it anyway,
    /// because "nothing reads it" is the argument that stopped being good
    /// enough when a forgery turned up in the trace height.
    #[test]
    fn a_tampered_export_flag_is_rejected() {
        use crate::wots_air::NUM_COLS;
        let (mut t, msg) = honest_trace(47, 57);
        // Column 0 of a mid-trace row. Honest traces carry ONE here.
        t.values[30 * NUM_COLS] = BabyBear::from_u32(9);
        must_not_verify(t, &msg, "a tampered export flag");
    }

    /// Zero-knowledge configuration proves and verifies through the same
    /// wrapper — the property SP1 cannot offer at any price.
    #[test]
    fn the_hiding_configuration_works() {
        let perm = wots::permutation();
        let seed = [33u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(13);
        let sig = wots::sign(&perm, &seed, &msg);

        let cfg = hiding_config();
        let proof = prove_hiding(&cfg, &msg, &sig);
        verify_hiding(&cfg, &proof, &msg, &pk).expect("hiding proof must verify");
        assert!(
            verify_hiding(&cfg, &proof, &msg_of(14), &pk).is_err(),
            "hiding config must bind the message too"
        );
    }

    // ---- Transfer-circuit negatives at the trace level ----
    //
    // The kernel2 wrapper's tests cover note-level attacks (inflation, asset
    // swap, foreign nullifier). These cover the constraint families only
    // reachable by tampering the trace itself.

    mod transfer {
        use super::*;
        use crate::sponge::{self, Domain};
        use crate::transfer_air::{AMT_O0, NUM_COLS as T_COLS, SP};
        use crate::transfer_trace::{self, NoteOpening, TransferWitness};
        use crate::wots_air::P2_COLS;

        fn limbs(v: u64) -> [BabyBear; 4] {
            core::array::from_fn(|i| BabyBear::from_u32(((v >> (16 * i)) & 0xFFFF) as u32))
        }

        fn open(tag: u32, amount_limbs: [BabyBear; 4]) -> NoteOpening {
            let perm = wots::permutation();
            let nk = [BabyBear::from_u32(tag * 3 + 1); 8];
            NoteOpening {
                amount_limbs,
                owner_pk: wots::public_key(&perm, &[tag as u8; 32]),
                anchor: sponge::hash(Domain::SpendAnchor, &nk),
                nullifier_key: nk,
                randomness: [BabyBear::from_u32(tag * 5 + 2); 8],
            }
        }

        fn commitment(asset: &wots::Digest, o: &NoteOpening) -> wots::Digest {
            let mut p = Vec::new();
            p.extend_from_slice(asset);
            p.extend_from_slice(&o.amount_limbs);
            p.extend_from_slice(&o.owner_pk);
            p.extend_from_slice(&o.anchor);
            p.extend_from_slice(&o.randomness);
            sponge::hash(Domain::Note, &p)
        }

        /// A witness whose publics are exactly what a verifier would derive —
        /// the most charitable statement the prover could hope for.
        fn consistent(
            in_limbs: [BabyBear; 4],
            o0: [BabyBear; 4],
            o1: [BabyBear; 4],
        ) -> (TransferWitness, TransferPublics) {
            let perm = wots::permutation();
            let asset = [BabyBear::from_u32(0xA5); 8];
            let input = open(31, in_limbs);
            let outs = [open(32, o0), open(33, o1)];
            let input_commitment = commitment(&asset, &input);
            let mut nf_pre = Vec::new();
            nf_pre.extend_from_slice(&input.nullifier_key);
            nf_pre.extend_from_slice(&input_commitment);
            let nullifier = sponge::hash(Domain::Nullifier, &nf_pre);
            let msg = [BabyBear::from_u32(0x1157); 8];
            let sig = wots::sign(&perm, &[31u8; 32], &msg);
            let publics = TransferPublics {
                input_commitment,
                nullifier,
                out0: commitment(&asset, &outs[0]),
                out1: commitment(&asset, &outs[1]),
                prev_history: [BabyBear::ZERO; 8],
                asset,
                msg,
            };
            (
                TransferWitness {
                    asset,
                    input,
                    outputs: outs,
                    msg,
                    sig,
                },
                publics,
            )
        }

        fn must_not_verify(
            t: p3_matrix::dense::RowMajorMatrix<BabyBear>,
            publics: &TransferPublics,
            what: &str,
        ) {
            let cfg = config();
            let tips = trace::tips_from_trace(&t);
            let pv = transfer_public_values(publics, &tips);
            let air = TransferAir::default();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                p3_prove(cfg.inner(), &air, t, &pv)
            })) {
                Err(_) => {}
                Ok(proof) => assert!(
                    p3_verify(cfg.inner(), &air, &proof, &pv).is_err(),
                    "{what} must never verify"
                ),
            }
        }

        /// Sanity: the synthetic witness is provable before any tampering, so
        /// the rejections below are the tamper's doing.
        #[test]
        fn the_synthetic_witness_is_honest() {
            let (w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            let t = transfer_trace::generate(&w);
            let cfg = config();
            let tips = trace::tips_from_trace(&t);
            let pv = transfer_public_values(&publics, &tips);
            let proof = p3_prove(cfg.inner(), &TransferAir::default(), t, &pv);
            p3_verify(cfg.inner(), &TransferAir::default(), &proof, &pv).expect("must verify");
        }

        /// Constraint 27: the amount bus must be constant across the section.
        /// A limb changed on one row — say, between its absorb row and the
        /// conservation row — must be rejected.
        #[test]
        fn a_tampered_amount_bus_is_rejected() {
            let (w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            let mut t = transfer_trace::generate(&w);
            let row = crate::wots_air::CHAIN_ROWS + 5;
            t.values[row * T_COLS + AMT_O0] += BabyBear::ONE;
            must_not_verify(t, &publics, "a bus limb changed mid-section");
        }

        /// Constraint 19: the section register is pinned by induction; a row
        /// re-labelled as a different sponge position must be rejected.
        #[test]
        fn a_shifted_sponge_register_is_rejected() {
            let (w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            let mut t = transfer_trace::generate(&w);
            let row = crate::wots_air::CHAIN_ROWS + 3;
            t.values[row * T_COLS + SP + 3] = BabyBear::ZERO;
            t.values[row * T_COLS + SP + 4] = BabyBear::ONE;
            must_not_verify(t, &publics, "a re-labelled sponge row");
        }

        /// Constraint 24: the capacity must carry between sponge rows. Rebuild
        /// one row's entire Poseidon2 block from a state whose capacity lane
        /// was bumped — the row is internally consistent, so only the
        /// cross-row carry constraint stands.
        #[test]
        fn a_broken_capacity_carry_is_rejected() {
            let (w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            let mut t = transfer_trace::generate(&w);
            let row = crate::wots_air::CHAIN_ROWS + 2; // continuing row of C_in
                                                       // Reconstruct the row's pre-permutation state, bump capacity lane 8.
            let mut state = [BabyBear::ZERO; wots::WIDTH];
            for (i, s) in state.iter_mut().enumerate() {
                *s = t.values[row * T_COLS + 1 + i]; // inputs start after `export`
            }
            state[8] += BabyBear::ONE;
            let p2 = trace::p2_columns(vec![state]);
            t.values[row * T_COLS..row * T_COLS + P2_COLS].copy_from_slice(&p2.values[..P2_COLS]);
            must_not_verify(t, &publics, "a discontinuous sponge capacity");
        }

        /// Constraint 32, the spend anchor. A payer knows the anchor `t` a
        /// note commits to, but not the key `nk` behind it. Supply a wrong
        /// `nk` — one whose hash is not the committed anchor — and the anchor
        /// row's output no longer matches the `T` bus that the commitment
        /// absorbed. This is what stops the payer spending the note it built,
        /// and what makes a published address safe to pay to.
        #[test]
        fn a_nullifier_key_that_does_not_open_the_anchor_is_rejected() {
            let (mut w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            // Keep the committed anchor; hand the circuit a different key.
            w.input.nullifier_key[0] += BabyBear::ONE;
            let t = transfer_trace::generate(&w);
            must_not_verify(t, &publics, "a key that does not open the anchor");
        }

        /// The mirror: a spender who supplies a real key but claims an anchor
        /// it does not hash to. The commitment would no longer open.
        #[test]
        fn a_forged_anchor_is_rejected() {
            let (mut w, publics) = consistent(limbs(100), limbs(60), limbs(40));
            w.input.anchor[0] += BabyBear::ONE;
            let t = transfer_trace::generate(&w);
            must_not_verify(t, &publics, "an anchor the key does not hash to");
        }

        /// Constraints 30+31, the limb range: a 2^16 limb satisfies
        /// conservation *with its carry* — 65536 = 0x10000 claimed in limb 0
        /// against an input whose value sits in limb 1 — and only the range
        /// check stands between that alias and verification. This is the
        /// attack the 16 shared bit columns exist to kill.
        #[test]
        fn an_aliased_limb_is_rejected() {
            let bad = [
                BabyBear::from_u32(1 << 16),
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ];
            // input = 65536 (limb1 = 1); output0 claims the same value as a
            // single out-of-range limb0; output1 = 0. Conservation holds with
            // carry(0) = 1; every sponge opens; only the range check objects.
            let (w, publics) = consistent(limbs(1 << 16), bad, limbs(0));
            let t = transfer_trace::generate(&w);
            must_not_verify(t, &publics, "a 2^16 limb alias");
        }
    }

    /// A proof whose tip count is wrong is rejected before anything else runs.
    #[test]
    fn a_wrong_tip_count_is_malformed() {
        let perm = wots::permutation();
        let seed = [66u8; 32];
        let pk = wots::public_key(&perm, &seed);
        let msg = msg_of(27);
        let sig = wots::sign(&perm, &seed, &msg);

        let cfg = config();
        let mut proof = prove(&cfg, &msg, &sig);
        proof.tips.pop();
        assert!(matches!(
            verify(&cfg, &proof, &msg, &pk),
            Err(Rejected::MalformedTips)
        ));
    }
}
