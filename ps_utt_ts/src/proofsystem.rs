use crate::commitment::{Commitment, CommitmentError};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

/// Proof of knowledge of a commitment in the G1 group
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

pub struct CommitmentProofs;

impl CommitmentProofs {}
