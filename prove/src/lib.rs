//! SP1 proving/verification for Ultraviolet transfers.
//!
//! Wraps the `uv-guest` program so the CLI can prove a genesis hop, prove a
//! chained hop on top of a received proof, and verify a received proof —
//! carrying proofs as opaque bytes across the wallet/transport layers. Raw
//! SP1 STARKs only; no SNARK wrapper (spec/04-PROOFS).

use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, ProveRequest, Prover as _, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey as _, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
};

use ultraviolet_kernel::history::{HopInput, HopOutput};
use ultraviolet_kernel::transfer::Transfer;

const GUEST_ELF: Elf = include_elf!("uv-guest");

/// A proven hop: the compressed recursive proof plus its committed
/// `HopOutput::encode()` bytes, both opaque to the wallet.
#[derive(Clone)]
pub struct ProvedHop {
    pub proof_bytes: Vec<u8>,
    pub hop_output_bytes: Vec<u8>,
}

impl ProvedHop {
    /// Decode the committed hop output.
    pub fn hop_output(&self) -> Option<HopOutput> {
        HopOutput::decode(&self.hop_output_bytes)
    }
}

/// Holds the prover client and the (single, constant) guest verifying key.
pub struct Prover {
    client: EnvProver,
    pk: EnvProvingKey,
    vkey: [u32; 8],
}

#[derive(Debug)]
pub enum ProveError {
    Prove(String),
    Verify(String),
    Decode,
    NotCompressed,
    VkeyMismatch,
}

impl Prover {
    /// Set up the prover (compiles/loads the guest verifying key once).
    pub fn new() -> Self {
        sp1_sdk::utils::setup_logger();
        let client: EnvProver = ProverClient::from_env();
        let pk = client.setup(GUEST_ELF).expect("guest setup");
        let vkey = pk.verifying_key().hash_u32();
        Prover { client, pk, vkey }
    }

    /// The guest verifying key (constant across a chain).
    pub fn vkey(&self) -> [u32; 8] {
        self.vkey
    }

    fn prove(&self, stdin: SP1Stdin) -> Result<ProvedHop, ProveError> {
        let proof = self
            .client
            .prove(&self.pk, stdin)
            .compressed()
            .run()
            .map_err(|e| ProveError::Prove(e.to_string()))?;
        let hop_output_bytes = proof.public_values.as_slice().to_vec();
        let proof_bytes =
            bincode::serialize(&proof).map_err(|e| ProveError::Prove(e.to_string()))?;
        Ok(ProvedHop { proof_bytes, hop_output_bytes })
    }

    /// Prove a genesis hop (issuance, or any transfer starting a fresh chain).
    pub fn prove_genesis(&self, transfer: &Transfer) -> Result<ProvedHop, ProveError> {
        let mut stdin = SP1Stdin::new();
        stdin.write(&HopInput::Genesis { transfer: transfer.clone(), vkey: self.vkey });
        self.prove(stdin)
    }

    /// Prove a chained hop: verify `prev`'s proof in-circuit, then this
    /// transfer. `prev` is what the wallet stored for the note being spent.
    pub fn prove_chained(
        &self,
        transfer: &Transfer,
        prev: &ProvedHop,
    ) -> Result<ProvedHop, ProveError> {
        let prev_proof: SP1ProofWithPublicValues =
            bincode::deserialize(&prev.proof_bytes).map_err(|_| ProveError::Decode)?;
        let prev_hop = prev.hop_output().ok_or(ProveError::Decode)?;

        let mut stdin = SP1Stdin::new();
        stdin.write(&HopInput::Chained {
            transfer: transfer.clone(),
            prev: prev_hop,
            vkey: self.vkey,
        });
        let SP1Proof::Compressed(p) = prev_proof.proof else {
            return Err(ProveError::NotCompressed);
        };
        stdin.write_proof(*p, self.pk.verifying_key().clone().vk);
        self.prove(stdin)
    }

    /// Verify a received proof and return its committed hop output. This is the
    /// receiver's entire validity check — one proof, any history depth.
    pub fn verify(&self, hop: &ProvedHop) -> Result<HopOutput, ProveError> {
        let proof: SP1ProofWithPublicValues =
            bincode::deserialize(&hop.proof_bytes).map_err(|_| ProveError::Decode)?;
        self.client
            .verify(&proof, self.pk.verifying_key(), None)
            .map_err(|e| ProveError::Verify(e.to_string()))?;
        let out = HopOutput::decode(proof.public_values.as_slice()).ok_or(ProveError::Decode)?;
        if out.vkey != self.vkey {
            return Err(ProveError::VkeyMismatch);
        }
        Ok(out)
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
