// use crate::commitment::Commitment;
use crate::commitment::Commitment;
use crate::error::Error;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use schnorr::schnorr::SchnorrProtocol;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: Commitment<E>,
    pub schnorr_commitment: E::G1Affine,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

impl<E: Pairing> CommitmentProof<E> {
    pub fn prove(
        pp: &PublicParams<E>,
        commitment: &Commitment<E>,
        messages: &[E::ScalarField],
        r: &E::ScalarField,
        rng: &mut impl Rng,
    ) -> Self {
        // Get bases and exponents for the proof
        let bases = pp.get_g1_bases();

        let mut exponents = messages.to_vec(); // Create a new vector with copies of messages
        exponents.push(*r); // Add r to the end (dereferenced)

        // Generate Schnorr commitment - add & to borrow the bases
        let schnorr_commitment = SchnorrProtocol::commit(&bases, rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &messages, &challenge);

        // create COmmitmentProof
        let proof: CommitmentProof<E> = CommitmentProof {
            commitment: commitment.clone(),
            schnorr_commitment: schnorr_commitment.commited_blindings,
            bases,
            challenge,
            responses: responses.0,
        };
        proof
    }

    pub fn verify(&self) -> bool {
        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify_schnorr(
            &self.bases,
            &self.commitment.cm,
            &self.schnorr_commitment,
            &self.responses,
            &self.challenge,
        );

        is_valid
    }
}
