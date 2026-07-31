//! Proving and verifying the transfer circuit ([`crate::authproto_air`]).
//!
//! FRI is configured at **blowup 16 / 25 queries** (~100-bit soundness), which
//! the Phase A sweep found to be the best point: prove time had ~50× headroom
//! against the gate, so spending it bought the smaller proof (`SPEC.md` §8).
//!
//! Two configurations, because they answer different questions:
//! - [`prove_authproto`] / [`verify_authproto`] — the standard STARK.
//! - [`prove_authproto_hiding`] / [`verify_authproto_hiding`] — blinded
//!   commitments and a randomized FRI, i.e. genuinely zero-knowledge. **This is
//!   the payment format**: the witness (the nullifier key) is fund-critical —
//!   it *is* the authorization (spec/99 `[PROOF-AUTH]`) — so hiding is not
//!   optional on the money path.

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_commit::Pcs as PcsTrait;
use p3_field::extension::BinomialExtensionField;
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

use crate::poseidon2;

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
/// [`verify_authproto_hiding`], which would verify against it without complaint.
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

/// FRI's blowup factor, as a log2. Larger means a more redundant codeword and
/// so more soundness per query, at proportionally more prover work.
const LOG_BLOWUP: usize = 4;
/// How many positions the verifier opens. Each independent query multiplies a
/// cheating prover's success probability by the code's rate.
const NUM_QUERIES: usize = 25;
/// Grinding the verifier makes the prover pay for each transcript it tries.
const QUERY_POW_BITS: usize = 16;

/// The soundness this configuration is chosen to hold, in bits.
///
/// **A target, and the number a reviewer should argue with** (`SPEC.md` §8.5).
const TARGET_SOUNDNESS_BITS: usize = 100;

/// Conjectured soundness of a FRI configuration, in bits.
///
/// `queries × log_blowup + grinding`. Each query independently catches a
/// prover whose committed word is far from the code with probability about the
/// rate `2^-log_blowup`, so `q` queries give `q · log_blowup` bits, and the
/// proof-of-work adds its bits directly.
///
/// **This is the conjectured bound, not the proven one, and the distinction is
/// the whole reason this function has a doc comment.** The proven bounds for
/// FRI are meaningfully worse than this heuristic; the heuristic is what the
/// STARK deployments this system is modelled on use in practice, and it is what
/// the numbers below were chosen against. If a reviewer holds us to proven
/// soundness, `NUM_QUERIES` goes up and prove time goes up with it — which is
/// affordable, since prove time has roughly 50× headroom against the gate. That
/// trade is available and unexercised, not unavailable.
pub const fn conjectured_soundness_bits(
    log_blowup: usize,
    num_queries: usize,
    query_pow_bits: usize,
) -> usize {
    num_queries * log_blowup + query_pow_bits
}

/// Why a FRI configuration was refused.
#[derive(Debug, PartialEq, Eq)]
pub struct FriTooWeak {
    pub bits: usize,
    pub required: usize,
}

/// Refuse a configuration that does not reach [`TARGET_SOUNDNESS_BITS`].
///
/// Takes the parameters rather than reading the constants, so a test can hand it
/// a **weakened** configuration and watch it refuse. A check that can only be
/// run against the values that already pass is not a check.
pub const fn check_fri_strength(
    log_blowup: usize,
    num_queries: usize,
    query_pow_bits: usize,
) -> Result<usize, FriTooWeak> {
    let bits = conjectured_soundness_bits(log_blowup, num_queries, query_pow_bits);
    if bits < TARGET_SOUNDNESS_BITS {
        return Err(FriTooWeak {
            bits,
            required: TARGET_SOUNDNESS_BITS,
        });
    }
    Ok(bits)
}

/// The shipped parameters must clear the target **at compile time.**
///
/// This is the defence the trace height had and these constants did not. Until
/// 2026-07-30 `NUM_QUERIES` could be edited to 1 and the entire workspace stayed
/// green: no test referenced it, and prover and verifier read the same constant,
/// so a two-bit proof verified happily. The trace height was the vector for this
/// project's only total forgery and it has a runtime check, a typed rejection and
/// a dedicated test file; these two had a comment.
///
/// A `const` assertion rather than a runtime one because both operands are
/// compile-time constants: weakening them should fail the *build*, not a test run
/// somebody might not do.
const _: () = assert!(
    check_fri_strength(LOG_BLOWUP, NUM_QUERIES, QUERY_POW_BITS).is_ok(),
    "FRI parameters fall below the target soundness (see SPEC.md 8.5)"
);

fn fri_params<M>(mmcs: M) -> FriParameters<M> {
    // Built from the same constants the assertion above vouches for, so there is
    // no path that reaches a PCS with parameters nothing checked.
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        num_queries: NUM_QUERIES,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
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

/// Reject any proof that does not declare exactly the height its AIR is sound at.
///
/// This is a consensus rule, and the second of them — the other being that
/// public values are built by the verifier from the transfer under validation.
/// It is the easier of the two to lose, because nothing in the AIR hints that
/// it exists. **A recursive verifier must reproduce both.** Without this one a
/// prover picks a height where the interesting constraints are gated off and
/// proves whatever it likes.
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

// ---- The transfer circuit ----

/// The public statement of one hop, as raw digests.
///
/// `uv-kernel2`'s wrapper derives this from a `Transfer` — including `msg` as
/// the transfer's own bundle hash — and is the consensus entry point. Calling
/// [`verify_authproto_hiding`] with a `msg` that is NOT the bundle hash of the
/// transfer being validated proves nothing about that transfer.
#[derive(Clone)]
pub struct TransferPublics {
    input_commitment: poseidon2::Digest,
    nullifier: poseidon2::Digest,
    out0: poseidon2::Digest,
    out1: poseidon2::Digest,
    prev_history: poseidon2::Digest,
    asset: poseidon2::Digest,
    /// The bundle hash. **Derived, never supplied.** Not read by any
    /// constraint; its binding is Fiat–Shamir over the public values, which is
    /// what makes the proof a signature of knowledge over *this* transfer.
    msg: poseidon2::Digest,
}

/// The bundle hash: what a record commits to, and the statement the spend
/// proof is Fiat–Shamir-bound to.
///
/// Defined here, beside the sponge, so there is exactly one definition.
/// `kernel2::transfer::Transfer::bundle_hash` delegates to it. Two definitions
/// of the thing a proof covers is a way for the proven thing and the validated
/// thing to drift apart.
pub fn bundle_hash(
    input_commitment: &poseidon2::Digest,
    nullifier: &poseidon2::Digest,
    prev_history: &poseidon2::Digest,
    outputs: &[poseidon2::Digest],
) -> poseidon2::Digest {
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
        input_commitment: poseidon2::Digest,
        nullifier: poseidon2::Digest,
        out0: poseidon2::Digest,
        out1: poseidon2::Digest,
        prev_history: poseidon2::Digest,
        asset: poseidon2::Digest,
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
    pub fn msg(&self) -> &poseidon2::Digest {
        &self.msg
    }
}

// ---------------------------------------------------------------------------
// Proof-native authorization (`crate::authproto_air`) — THE money path.
//
// This block was written when these functions were a measurement prototype and
// its header said so: "deliberately NOT consensus, nothing in the wallet calls
// these." Every clause of that is now false. The wallet calls them, money moves
// on them, and `air/mutants.py` sweeps all sixteen constraints (16 of 16
// killed). Corrected 2026-07-30; a comment claiming a consensus function is a
// toy is worse than no comment.
// ---------------------------------------------------------------------------

/// A money-path proof. No tips: there is no signature for tips to belong to,
/// and authorization is the anchor-preimage constraint plus the Fiat–Shamir
/// binding of every public value, the bundle hash included.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuthProtoProof {
    pub stark: Proof<Config>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct HidingAuthProtoProof {
    pub stark: Proof<HidingConfig>,
}

/// Trace bits for the prototype: 18 sponge rows padded to 32.
pub const AUTHPROTO_DEGREE_BITS: usize = crate::authproto_air::HEIGHT.trailing_zeros() as usize;

/// Public values for the transfer statement: the four commitments/nullifier,
/// the prev-history digest, the asset, and the bundle hash. No tips (no
/// signature) and no owner_pk (dropped from the note).
fn authproto_public_values(publics: &TransferPublics) -> Vec<Val> {
    let mut pv = Vec::with_capacity(crate::authproto_air::NUM_PUBLIC_VALUES);
    for part in [
        &publics.input_commitment,
        &publics.nullifier,
        &publics.out0,
        &publics.out1,
        &publics.prev_history,
        &publics.asset,
        &publics.msg,
    ] {
        pv.extend_from_slice(part.as_slice());
    }
    assert_eq!(pv.len(), crate::authproto_air::NUM_PUBLIC_VALUES);
    pv
}

pub fn prove_authproto(
    config: &Vouched<Config>,
    witness: &crate::transfer_trace::TransferWitness,
    publics: &TransferPublics,
) -> AuthProtoProof {
    let trace = crate::authproto_air::generate(witness);
    let pv = authproto_public_values(publics);
    let stark = p3_prove(
        config.inner(),
        &crate::authproto_air::AuthProtoAir::default(),
        trace,
        &pv,
    );
    AuthProtoProof { stark }
}

pub fn verify_authproto(
    config: &Vouched<Config>,
    proof: &AuthProtoProof,
    publics: &TransferPublics,
) -> Result<(), Rejected<VerifyError<Config>>> {
    check_height(
        config.inner(),
        proof.stark.degree_bits,
        AUTHPROTO_DEGREE_BITS,
    )?;
    let pv = authproto_public_values(publics);
    catching_panics(|| {
        p3_verify(
            config.inner(),
            &crate::authproto_air::AuthProtoAir::default(),
            &proof.stark,
            &pv,
        )
    })
}

pub fn prove_authproto_hiding(
    config: &Vouched<HidingConfig>,
    witness: &crate::transfer_trace::TransferWitness,
    publics: &TransferPublics,
) -> HidingAuthProtoProof {
    let trace = crate::authproto_air::generate(witness);
    let pv = authproto_public_values(publics);
    let stark = p3_prove(
        config.inner(),
        &crate::authproto_air::AuthProtoAir::default(),
        trace,
        &pv,
    );
    HidingAuthProtoProof { stark }
}

pub fn verify_authproto_hiding(
    config: &Vouched<HidingConfig>,
    proof: &HidingAuthProtoProof,
    publics: &TransferPublics,
) -> Result<(), Rejected<VerifyError<HidingConfig>>> {
    check_height(
        config.inner(),
        proof.stark.degree_bits,
        AUTHPROTO_DEGREE_BITS,
    )?;
    let pv = authproto_public_values(publics);
    catching_panics(|| {
        p3_verify(
            config.inner(),
            &crate::authproto_air::AuthProtoAir::default(),
            &proof.stark,
            &pv,
        )
    })
}
