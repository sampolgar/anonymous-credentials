// first define opening of a commitment protocol
// then define equality of commitment protocol with multiple commitments and opening of position 0 of the commitment being equality

use crate::commitment::Commitment;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
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
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentEqualityProof<E: Pairing> {
    pub commitments: Vec<E::G1Affine>,
    pub schnorr_commitments: Vec<E::G1Affine>,
    pub bases: Vec<Vec<E::G1Affine>>,
    pub challenge: E::ScalarField,
    pub responses: Vec<Vec<E::ScalarField>>,
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
        let schnorr_commitment = SchnorrProtocol::commit(&bases.clone(), &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.cmg1,
            schnorr_commitment: schnorr_commitment.com_t,
            bases: bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn verify_knowledge<E: Pairing>(
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

    // for testing, we hard-code the equality index to 0, meaning we are checking if index 0 is the same
    pub fn prove_equality<E: Pairing>(
        commitments: &[Commitment<E>],
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // generate schnorr commitment per Commitment, use equal blindness for equality proofs at index 0
        let mut schnorr_equality_commitments = Vec::new();
        let mut responses: Vec<SchnorrResponses<E::G1Affine>> = Vec::new();
        let equal_blindness = E::ScalarField::rand(&mut rng);

        // generate Schnorr Commitments
        for (i, commitment) in commitments.iter().enumerate() {
            let bases_i = commitment.pp.get_g1_bases();
            let schnorr_commitment_i =
                SchnorrProtocol::commit_equality(&bases_i, &mut rng, &equal_blindness, 0);
            schnorr_equality_commitments.push(schnorr_commitment_i);
        }

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        for i in 0..commitments.len() {
            let commitment = &commitments[i];
            let schnorr_commitment = &schnorr_equality_commitments[i];
            let response = SchnorrProtocol::prove(
                &schnorr_commitment,
                &commitment.get_exponents(),
                &challenge,
            );
            schnorr_equality_commitments.push(schnorr_commitment.clone());
            responses.push(response.clone());
        }

        let equality_proof: CommitmentEqualityProof<E> = CommitmentEqualityProof {
            commitments: commitments.iter().map(|c| c.cmg1).collect(),
            schnorr_commitments: schnorr_equality_commitments
                .iter()
                .map(|sc| sc.com_t)
                .collect(),
            bases: commitments
                .iter()
                .map(|cms| cms.pp.get_g1_bases())
                .collect(),
            challenge,
            responses: responses.iter().map(|r| r.0.clone()).collect(),
        };

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        equality_proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn verify_equality<E: Pairing>(
        serialized_proof: &[u8],
    ) -> Result<bool, CommitmentProofError> {
        // Deserialize the proof
        let proof: CommitmentEqualityProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // First verify each individual commitment
        for i in 0..proof.commitments.len() {
            // Create schnorr commitment struct for verification
            // Verify the individual proof
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

    pub fn prove_zero<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();
        // take in a commitment C = g1^mg2h^r, generate T = g1^a g2 h^rho
        let bases = commitment.pp.get_g1_bases();
        let exponents = commitment.get_exponents();
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let challenge = E::ScalarField::rand(&mut rng);
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.cmg1,
            schnorr_commitment: schnorr_commitment.com_t,
            bases: bases,
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

        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let messages: Vec<_> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);

        let commitment = Commitment::new(&pp, &messages, &r);

        let proof = CommitmentProofs::prove_knowledge(&commitment).unwrap();
        assert!(CommitmentProofs::verify_knowledge::<Bls12_381>(&proof).unwrap());
    }

    #[test]
    fn test_commitment_equality_proofs_2() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp1 = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let pp2 = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);

        // Create two commitments with same message at index 1
        let shared_message = Fr::rand(&mut rng);
        let mut messages1: Vec<_> = (0..pp1.n).map(|_| Fr::rand(&mut rng)).collect();
        let mut messages2: Vec<_> = (0..pp2.n).map(|_| Fr::rand(&mut rng)).collect();
        messages1[0] = shared_message;
        messages2[0] = shared_message;

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        let commitment1 = Commitment::new(&pp1, &messages1, &r1);
        let commitment2 = Commitment::new(&pp2, &messages2, &r2);

        let proof = CommitmentProofs::prove_equality(&[commitment1, commitment2]).unwrap();
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

        // Create a shared message that will be at index 0 in all commitments
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

        // Optional: Test that proof fails with different messages
        let mut invalid_messages = messages[0].clone();
        invalid_messages[0] = Fr::rand(&mut rng);
        let invalid_commitment =
            Commitment::new(&public_params[0], &invalid_messages, &blinding_factors[0]);

        let mut invalid_commitments = commitments.clone();
        invalid_commitments[0] = invalid_commitment;

        let invalid_proof = CommitmentProofs::prove_equality(&invalid_commitments);
        assert!(
            invalid_proof.is_err()
                || !CommitmentProofs::verify_equality::<Bls12_381>(&invalid_proof.unwrap())
                    .unwrap()
        );
    }

    #[test]
    pub fn test_multiplicative_inv() {
        let mut rng = ark_std::test_rng();
        let k = Fr::rand(&mut rng);
        let context_master = Fr::rand(&mut rng);
        let context_dmv = Fr::rand(&mut rng);

        let m1 = Fr::rand(&mut rng);
        let m2 = m1.neg();
        assert!((m1 + m2).is_zero(), "m1 + m2 not zero");

        let s = Fr::rand(&mut rng);
        let delta = k + context_dmv;

        // create commitments
        let pp1 = PublicParams::<Bls12_381>::new(&4, &context_master, &mut rng);
        let pp2 = PublicParams::<Bls12_381>::new(&4, &context_dmv, &mut rng);

        let 
        // create cm1 = Com([m1, master, m3, m4], r1)
        // create cm2 = Com([s, dmv, m3, m4], r2)

        // generate VRF, use get_delta to output

        // prove cm1 has s+master, cm2 has
    }
}
