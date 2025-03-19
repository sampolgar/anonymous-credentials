use crate::commitment::{Commitment, CommitmentKey};
use crate::proof::CommitmentProof;
use crate::public_params::PublicParams;
use crate::signature::Signature;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialState {
    Initialized, // Just created with attributes
    Committed,   // Commitments generated
    Signed,      // Has valid signature
    Randomized,  // Has been shown/randomized
}

pub struct Credential<E: Pairing> {
    pub commitment: Commitment<E>,
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
    signature: Option<Signature<E>>,
}

impl<E: Pairing> Credential<E> {
    pub fn new(
        ck: &CommitmentKey<E>,
        pp: &PublicParams<E>,
        messages: &[E::ScalarField],
        r: E::ScalarField,
    ) -> Self {
        let commitment = ck.commit(pp, messages, &r);

        Self {
            commitment,
            messages: messages.to_vec(),
            r,
            signature: None,
        }
    }
    pub fn prove(&self, pp: &PublicParams<E>, rng: &mut impl Rng) -> CommitmentProof<E> {
        CommitmentProof::prove(&pp, &self.commitment, &self.messages, &self.r, rng)
    }
}
