use crate::commitment::{Commitment, CommitmentError, CommitmentProof};
use crate::symmetric_commitment::{SymmetricCommitment, SymmetricCommitmentKey};
use crate::verifier::VerificationError;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand::Rng, vec::Vec, UniformRand};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid share from party {0}")]
    InvalidShare(usize),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Failed to deserialize proof")]
    DeserializationError,
    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),
    #[error("Proof Verify Error")]
    ProofVerifyError,
}
pub struct CommitmentProofs;

impl CommitmentProofs {
    pub fn pok_commitment_prove<E: Pairing>(
        commitment: &Commitment<E>,
        rng: &mut impl Rng,
    ) -> Result<Vec<u8>, CommitmentError> {
        let schnorr_commitment = SchnorrProtocol::commit(&commitment.bases, rng);
        let challenge = E::ScalarField::rand(rng);
        let responses =
            SchnorrProtocol::prove(&schnorr_commitment, &commitment.exponents, &challenge);

        let proof: CommitmentProof<E> = CommitmentProof {
            bases: commitment.bases.clone(),
            commitment: commitment.cm,
            schnorr_commitment,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof of knowledge for a commitment
    pub fn pok_commitment_verify<E: Pairing>(serialized_proof: &[u8]) -> Result<bool, ProofError> {
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)
                .map_err(|_| ProofError::DeserializationError)?;

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        if !is_valid {
            return Err(ProofError::ProofVerifyError);
        }

        Ok(is_valid)
    }
}
