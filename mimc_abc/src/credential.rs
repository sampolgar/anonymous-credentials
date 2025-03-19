// use crate::commitment::{Commitment, CommitmentProof};
use crate::commitment::Commitment;
use crate::proof::CommitmentProof;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

pub struct Credential<E: Pairing> {
    pub commitment: Commitment<E>,
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
}

impl<E: Pairing> Credential<E> {
    pub fn prove(&self, pp: &PublicParams<E>, rng: &mut impl Rng) -> CommitmentProof<E> {
        CommitmentProof::prove(&pp, &self.commitment, &self.messages, &self.r, rng)
    }
}

// pub struct Signature<E: Pairing> {
//     // Signature fields
// }

// impl<E: Pairing> Signature<E> {
//     pub fn verify(&self, commitment: &Commitment<E>, pk: &PublicKey<E>) -> bool {
//         // Verify signature on commitment
//     }
// }
