use crate::commitment::Commitment;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

/// Possible errors that can occur during commitment proof operations
#[derive(Error, Debug)]
pub enum CommitmentProofError {
    /// The commitment is invalid
    #[error("Invalid commitment")]
    InvalidCommitment,

    /// The proof is invalid
    #[error("Invalid proof")]
    InvalidProof,

    /// The provided index for an equality proof is invalid
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,

    /// Commitments in a batch have different lengths
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,

    /// An error occurred during serialization or deserialization
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Proof of knowledge of a commitment in the G1 group
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    /// The commitment value in G1
    pub commitment: E::G1Affine,

    /// The Schnorr commitment
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,

    /// The bases used in the commitment
    pub bases: Vec<E::G1Affine>,

    /// Challenge value used in the proof
    pub challenge: E::ScalarField,

    /// Response values used in the proof
    pub responses: Vec<E::ScalarField>,
}

pub struct CommitmentProofs;

impl CommitmentProofs {
    /// Generate a proof of knowledge of a commitment in G1
    ///
    /// # Arguments
    /// * `commitment` - The commitment to prove knowledge of
    ///
    /// # Returns
    /// A serialized proof
    pub fn pok_commitment_prove<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Get bases and exponents for the proof
        let bases = commitment.get_bases();
        let exponents = commitment.get_exponents();

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.commitment,
            schnorr_commitment,
            bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof of knowledge of a commitment in G1
    ///
    /// # Arguments
    /// * `serialized_proof` - The serialized proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn pok_commitment_verify<E: Pairing>(
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use ark_bls12_381::{Bls12_381, Fr};
    #[test]
    fn test_commitment_proof_system_integration() {
        // Initialize test environment
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create random messages and blinding factor
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let t = Fr::rand(&mut rng);

        // Create commitment
        let commitment = Commitment::new(&pp, &pk, &messages, &t);

        // Generate proof of knowledge
        let proof = commitment
            .prove_opening()
            .expect("Proof generation should succeed");

        // Verify the proof
        let is_valid = CommitmentProofs::pok_commitment_verify::<Bls12_381>(&proof)
            .expect("Proof verification should complete");

        assert!(is_valid, "Commitment proof verification should succeed");

        // Manual verification of the Schnorr proof components
        let proof_obj: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&proof[..])
                .expect("Proof deserialization failed");

        // Verify the bases and commitment in the proof
        assert_eq!(
            proof_obj.commitment, commitment.commitment,
            "Proof commitment should match original"
        );
        assert_eq!(
            proof_obj.bases.len(),
            n + 1,
            "Proof should have correct number of bases"
        );

        // Verify the Schnorr validation equation manually
        let schnorr_valid = SchnorrProtocol::verify(
            &proof_obj.bases,
            &proof_obj.commitment,
            &proof_obj.schnorr_commitment,
            &SchnorrResponses(proof_obj.responses.clone()),
            &proof_obj.challenge,
        );

        assert!(
            schnorr_valid,
            "Manual verification of Schnorr proof should succeed"
        );
    }
}
