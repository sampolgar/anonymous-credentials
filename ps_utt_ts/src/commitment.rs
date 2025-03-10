// use crate::proofsystem::{CommitmentProof, CommitmentProofError, CommitmentProofs};
use crate::shamir::generate_shares;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Invalid Commit Process")]
    InvalidComputeCommitment,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Commitment<E: Pairing> {
    pub bases: Vec<E::G1Affine>,
    pub exponents: Vec<E::ScalarField>,
    pub cm: E::G1Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

impl<E: Pairing> Commitment<E> {
    pub fn new(
        h: &E::G1Affine,
        g: &E::G1Affine,
        m: &E::ScalarField,
        r_opt: Option<E::ScalarField>,
        rng: &mut impl Rng,
    ) -> Self {
        let r = match r_opt {
            Some(r_value) => r_value,
            None => E::ScalarField::rand(rng),
        };

        // gen commitment
        let cm = (h.mul(m) + g.mul(r)).into_affine();
        let bases = vec![*h, *g];
        let exponents = vec![*m, r];
        Self {
            bases,
            exponents,
            cm,
        }
    }

    pub fn prove(self, rng: &mut impl Rng) -> Result<Vec<u8>, CommitmentError> {
        let schnorr_commitment = SchnorrProtocol::commit(&self.bases, rng);
        let challenge = E::ScalarField::rand(rng);
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &self.exponents, &challenge);
        let proof: CommitmentProof<E> = CommitmentProof {
            bases: self.bases,
            commitment: self.cm,
            schnorr_commitment,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn pok_commitment_verify(serialized_proof: &[u8]) -> Result<bool, CommitmentError> {
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
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_basic_commitment_and_proof() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate random base points
        let h = G1Affine::rand(&mut rng);
        let g = G1Affine::rand(&mut rng);

        // Generate a random message
        let m = Fr::rand(&mut rng);

        // Create a commitment
        let commitment = Commitment::<Bls12_381>::new(&h, &g, &m, None, &mut rng);

        // Check that commitment was created correctly
        assert_eq!(commitment.bases.len(), 2, "Should have 2 bases");
        assert_eq!(commitment.exponents.len(), 2, "Should have 2 exponents");
        assert_eq!(commitment.bases[0], h, "First base should be h");
        assert_eq!(commitment.bases[1], g, "Second base should be g");
        assert_eq!(commitment.exponents[0], m, "First exponent should be m");

        // Manually verify the commitment computation
        let r = commitment.exponents[1];
        let expected_cm = (h.mul(&m) + g.mul(&r)).into_affine();
        assert_eq!(
            commitment.cm, expected_cm,
            "Commitment calculation incorrect"
        );

        // Generate a proof
        let serialized_proof = commitment.prove(&mut rng).unwrap();

        // Verify the proof by deserializing and checking
        let proof: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof[..]).unwrap();

        // Verify the proof using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        assert!(is_valid, "Proof verification failed");

        // Test with specific blinding factor
        let specific_r = Fr::rand(&mut rng);
        let commitment_with_r =
            Commitment::<Bls12_381>::new(&h, &g, &m, Some(specific_r), &mut rng);

        // Check that the specific blinding was used
        assert_eq!(
            commitment_with_r.exponents[1], specific_r,
            "Custom randomness not used"
        );

        // Generate and verify proof for this commitment too
        let serialized_proof_2 = commitment_with_r.prove(&mut rng).unwrap();
        let proof_2: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof_2[..]).unwrap();

        let is_valid_2 = SchnorrProtocol::verify(
            &proof_2.bases,
            &proof_2.commitment,
            &proof_2.schnorr_commitment,
            &SchnorrResponses(proof_2.responses.clone()),
            &proof_2.challenge,
        );

        assert!(
            is_valid_2,
            "Proof verification failed for commitment with specific randomness"
        );
    }
}
