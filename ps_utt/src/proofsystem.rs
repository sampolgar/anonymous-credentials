// first define opening of a commitment protocol
// then define equality of commitment protocol with multiple commitments and opening of position 0 of the commitment being equality

use crate::commitment::Commitment;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommitmentProofError {
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: E::G1Affine,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentEqualityProof<E: Pairing> {
    pub commitments: Vec<E::G1Affine>,
    pub schnorr_commitment: E::G1Affine,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
    pub equality_indices: Vec<(usize, usize)>, // (commitment_idx, message_idx)
}

pub struct CommitmentProofs;

impl CommitmentProofs {
    pub fn prove_knowledge<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Get bases and exponents for the proof
        let bases = commitment.pp.get_g1_bases();
        let exponents = commitment.get_exponents();

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.cmg1,
            schnorr_commitment: schnorr_commitment.com_t,
            challenge,
            responses: responses.0,
        };

        // test intermediately
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &commitment.cmg1,
            &schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &challenge,
        );

        assert!(is_valid, "interim proof isn't valid commitment");

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn verify_knowledge<E: Pairing>(
        pp: &PublicParams<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Get bases for verification
        let bases = pp.get_g1_bases();

        // Create a SchnorrCommitment struct for verification
        let schnorr_commitment = SchnorrCommitment {
            random_blindings: vec![], // We don't need the blindings for verification
            com_t: proof.schnorr_commitment,
        };

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &proof.commitment,
            &schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        Ok(is_valid)
    }

    pub fn prove_equality<E: Pairing>(
        commitments: &[Commitment<E>],
        equality_indices: &[(usize, usize)],
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Validate indices
        for &(comm_idx, msg_idx) in equality_indices {
            if comm_idx >= commitments.len() || msg_idx >= commitments[0].messages.len() {
                return Err(CommitmentProofError::InvalidEqualityIndex);
            }
        }

        // Collect all bases and exponents
        let mut all_bases = Vec::new();
        let mut all_exponents = Vec::new();

        for commitment in commitments {
            all_bases.extend(commitment.pp.get_g1_bases());
            all_exponents.extend(commitment.get_exponents());
        }

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&all_bases, &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &all_exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentEqualityProof<E> = CommitmentEqualityProof {
            commitments: commitments.iter().map(|c| c.cmg1).collect(),
            schnorr_commitment: schnorr_commitment.com_t, // Fixed: Using com_t instead of t
            challenge,
            responses: responses.0,
            equality_indices: equality_indices.to_vec(),
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    // verify_equality implementation remains the same but needs the schnorr_commitment struct update
    pub fn verify_equality<E: Pairing>(
        pps: &[PublicParams<E>],
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        let proof: CommitmentEqualityProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Validate number of commitments matches number of public parameters
        if proof.commitments.len() != pps.len() {
            return Err(CommitmentProofError::MismatchedCommitmentLengths);
        }

        // Collect all bases
        let mut all_bases = Vec::new();
        for pp in pps {
            all_bases.extend(pp.get_g1_bases());
        }

        // Create a SchnorrCommitment struct for verification
        let schnorr_commitment = SchnorrCommitment {
            random_blindings: vec![], // We don't need the blindings for verification
            com_t: proof.schnorr_commitment,
        };

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &all_bases,
            &proof.commitments[0], // Use first commitment as reference
            &schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        // Verify equality constraints
        for &(comm_idx1, msg_idx1) in &proof.equality_indices {
            for &(comm_idx2, msg_idx2) in &proof.equality_indices {
                if comm_idx1 != comm_idx2 {
                    if proof.responses[msg_idx1] != proof.responses[msg_idx2] {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_commitment_knowledge_proof() {
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&4, &mut rng);
        let messages: Vec<_> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);

        let commitment = Commitment::new(&pp, &messages, &r);

        let proof = CommitmentProofs::prove_knowledge(&commitment).unwrap();
        assert!(CommitmentProofs::verify_knowledge(&pp, &proof).unwrap());
    }

    #[test]
    fn test_commitment_equality_proof() {
        let mut rng = ark_std::test_rng();
        let pp1 = PublicParams::<Bls12_381>::new(&4, &mut rng);
        let pp2 = PublicParams::<Bls12_381>::new(&4, &mut rng);

        // Create two commitments with same message at index 1
        let shared_message = Fr::rand(&mut rng);
        let mut messages1: Vec<_> = (0..pp1.n).map(|_| Fr::rand(&mut rng)).collect();
        let mut messages2: Vec<_> = (0..pp2.n).map(|_| Fr::rand(&mut rng)).collect();
        messages1[1] = shared_message;
        messages2[1] = shared_message;

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        let commitment1 = Commitment::new(&pp1, &messages1, &r1);
        let commitment2 = Commitment::new(&pp2, &messages2, &r2);

        let equality_indices = vec![(0, 1), (1, 1)]; // Message at index 1 should be equal
        let proof =
            CommitmentProofs::prove_equality(&[commitment1, commitment2], &equality_indices)
                .unwrap();
        assert!(CommitmentProofs::verify_equality(&[pp1, pp2], &proof).unwrap());
    }
}
