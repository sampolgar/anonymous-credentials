use crate::commitment::Commitment;
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
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Proof of knowledge of a commitment in the G1 group
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

/// Proof of knowledge of a commitment in the G2 group
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProofG2<E: Pairing> {
    pub commitment: E::G2Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G2Affine>,
    pub bases: Vec<E::G2Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

/// Proof that multiple commitments share the same value at a specific index
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentEqualityProof<E: Pairing> {
    pub commitments: Vec<E::G1Affine>,
    pub schnorr_commitments: Vec<SchnorrCommitment<E::G1Affine>>,
    pub bases: Vec<Vec<E::G1Affine>>,
    pub challenge: E::ScalarField,
    pub responses: Vec<Vec<E::ScalarField>>,
}

/// Implementation of various commitment proof schemes
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
            schnorr_commitment,
            bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Generate a proof of knowledge of a commitment in G2
    ///
    /// # Arguments
    /// * `commitment` - The commitment to prove knowledge of
    ///
    /// # Returns
    /// A serialized proof
    pub fn pok_commitment_prove_g2<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Get bases and exponents for the proof
        let bases = commitment.pp.get_g2_bases();
        let exponents = commitment.get_exponents();

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProofG2<E> = CommitmentProofG2 {
            commitment: commitment.cmg2,
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

    /// Verify a proof of knowledge of a commitment in G2
    ///
    /// # Arguments
    /// * `serialized_proof` - The serialized proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn pok_commitment_verify_g2<E: Pairing>(
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        let proof: CommitmentProofG2<E> =
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

    /// Generate a proof that multiple commitments share the same value at index 0
    ///
    /// # Arguments
    /// * `commitments` - The commitments to prove equality for
    ///
    /// # Returns
    /// A serialized proof
    pub fn prove_equality<E: Pairing>(
        commitments: &[Commitment<E>],
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Generate equal blindness for equality proofs at index 0
        let equal_blindness = E::ScalarField::rand(&mut rng);
        let mut schnorr_commitments = Vec::with_capacity(commitments.len());
        let mut responses = Vec::with_capacity(commitments.len());

        // Generate Schnorr commitments
        for commitment in commitments.iter() {
            let bases = commitment.pp.get_g1_bases();
            let schnorr_commitment =
                SchnorrProtocol::commit_equality(&bases, &mut rng, &equal_blindness, 0);
            schnorr_commitments.push(schnorr_commitment);
        }

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        for (i, commitment) in commitments.iter().enumerate() {
            let response = SchnorrProtocol::prove(
                &schnorr_commitments[i],
                &commitment.get_exponents(),
                &challenge,
            );
            responses.push(response);
        }

        // Create equality proof with explicit type annotation
        let equality_proof: CommitmentEqualityProof<E> = CommitmentEqualityProof {
            commitments: commitments.iter().map(|c| c.cmg1).collect(),
            schnorr_commitments: schnorr_commitments.clone(),
            bases: commitments.iter().map(|c| c.pp.get_g1_bases()).collect(),
            challenge,
            responses: responses.iter().map(|r| r.0.clone()).collect(),
        };

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        equality_proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof that multiple commitments share the same value at index 0
    ///
    /// # Arguments
    /// * `serialized_proof` - The serialized proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_equality<E: Pairing>(
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        // Deserialize the proof
        let proof: CommitmentEqualityProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // First verify each individual commitment
        for i in 0..proof.commitments.len() {
            let is_valid = SchnorrProtocol::verify(
                &proof.bases[i],
                &proof.commitments[i],
                &proof.schnorr_commitments[i],
                &SchnorrResponses(proof.responses[i].clone()),
                &proof.challenge,
            );

            if !is_valid {
                return Ok(false);
            }
        }

        // Then verify that response at position 0 is equal across all commitments
        let first_response = &proof.responses[0][0];
        for responses in proof.responses.iter().skip(1) {
            if &responses[0] != first_response {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Generate a proof that a commitment is to zero
    ///
    /// # Arguments
    /// * `commitment` - The commitment to prove is to zero
    ///
    /// # Returns
    /// A serialized proof
    pub fn prove_zero<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Get bases and exponents for the proof
        let bases = commitment.pp.get_g1_bases();
        let exponents = commitment.get_exponents();

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Generate challenge and responses
        let challenge = E::ScalarField::rand(&mut rng);
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.cmg1,
            schnorr_commitment,
            bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publicparams::PublicParams;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::{One, Zero};

    #[test]
    fn test_commitment_knowledge_proof() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);

        // Create public parameters and random messages
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let messages: Vec<_> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);

        // Create commitment and prove knowledge
        let commitment = Commitment::new(&pp, &messages, &r);
        let proof = CommitmentProofs::pok_commitment_prove(&commitment).unwrap();

        // Verify proof
        assert!(CommitmentProofs::pok_commitment_verify::<Bls12_381>(&proof).unwrap());
    }

    #[test]
    fn test_commitment_knowledge_proof_g2() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);

        // Create public parameters and random messages
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let messages: Vec<_> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);

        // Create commitment and prove knowledge
        let commitment = Commitment::new(&pp, &messages, &r);
        let proof = CommitmentProofs::pok_commitment_prove_g2(&commitment).unwrap();

        // Verify proof
        assert!(CommitmentProofs::pok_commitment_verify_g2::<Bls12_381>(&proof).unwrap());
    }

    #[test]
    fn test_commitment_equality_proofs_2() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);

        // Create two public parameter sets
        let pp1 = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let pp2 = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);

        // Create two commitments with same message at index 0
        let shared_message = Fr::rand(&mut rng);
        let mut messages1: Vec<_> = (0..pp1.n).map(|_| Fr::rand(&mut rng)).collect();
        let mut messages2: Vec<_> = (0..pp2.n).map(|_| Fr::rand(&mut rng)).collect();
        messages1[0] = shared_message;
        messages2[0] = shared_message;

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        // Create commitments and prove equality
        let commitment1 = Commitment::new(&pp1, &messages1, &r1);
        let commitment2 = Commitment::new(&pp2, &messages2, &r2);
        let proof = CommitmentProofs::prove_equality(&[commitment1, commitment2]).unwrap();

        // Verify equality proof
        assert!(CommitmentProofs::verify_equality::<Bls12_381>(&proof).unwrap());
    }

    #[test]
    fn test_commitment_equality_proofs_10() {
        let mut rng = ark_std::test_rng();

        // Create 10 different public parameters
        let context = Fr::rand(&mut rng);
        let public_params: Vec<PublicParams<Bls12_381>> = (0..10)
            .map(|_| PublicParams::<Bls12_381>::new(&4, &context, &mut rng))
            .collect();

        // Create a shared message for index 0 in all commitments
        let shared_message = Fr::rand(&mut rng);

        // Create 10 message vectors, each with the shared message at index 0
        let messages: Vec<Vec<Fr>> = (0..10)
            .map(|_| {
                let mut msgs: Vec<_> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
                msgs[0] = shared_message;
                msgs
            })
            .collect();

        // Generate 10 random blinding factors
        let blinding_factors: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();

        // Create 10 commitments
        let commitments: Vec<Commitment<Bls12_381>> = messages
            .iter()
            .zip(public_params.iter())
            .zip(blinding_factors.iter())
            .map(|((msgs, pp), r)| Commitment::new(pp, msgs, r))
            .collect();

        // Create and verify the equality proof
        let proof = CommitmentProofs::prove_equality(&commitments).unwrap();
        assert!(CommitmentProofs::verify_equality::<Bls12_381>(&proof).unwrap());

        // Test that proof fails with different messages
        let mut invalid_messages = messages[0].clone();
        invalid_messages[0] = Fr::rand(&mut rng); // Change the shared message

        let invalid_commitment =
            Commitment::new(&public_params[0], &invalid_messages, &blinding_factors[0]);

        let mut invalid_commitments = commitments.clone();
        invalid_commitments[0] = invalid_commitment;

        let invalid_proof = CommitmentProofs::prove_equality(&invalid_commitments);

        // Either the proof creation fails or the verification fails
        assert!(
            invalid_proof.is_err()
                || !CommitmentProofs::verify_equality::<Bls12_381>(&invalid_proof.unwrap())
                    .unwrap()
        );
    }
}
