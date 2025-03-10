// includes threshold_signature operations
//
use crate::commitment::{Commitment, CommitmentError};
use crate::keygen::{keygen, SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare};
use crate::symmetric_commitment::{SymmetricCommitment, SymmetricCommitmentKey};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One,
};
use thiserror::Error;
use utils::pairing::PairingCheck;

#[derive(Clone, Debug)]
pub struct PartialSignature<E: Pairing> {
    pub h: E::G1Affine,
    pub party_index: usize,
    pub sigma: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdSignature<E: Pairing> {
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

#[derive(Debug)]
pub enum ThresholdSignatureError {
    /// Error in serialization
    SerializationError(SerializationError),
    /// Error in commitment
    CommitmentError(CommitmentError),
    /// Error from invalid share
    InvalidShare(usize),
    /// Error from having duplicate shares,
    DuplicateShare(usize),
    /// Threshold not met
    ThresholdNotMet,
}

impl From<CommitmentError> for ThresholdSignatureError {
    fn from(err: CommitmentError) -> Self {
        ThresholdSignatureError::CommitmentError(err)
    }
}

pub fn compute_lagrange_coefficient<F: Field>(indices: &[usize], j: usize) -> F {
    let j_field = F::from(j as u64);

    let mut result = F::one();
    for &i in indices {
        if i == j {
            continue;
        }

        let i_field = F::from(i as u64);
        let numerator = i_field;
        let denominator = j_field - i_field;

        // Compute i/(j-i)
        result *= numerator * denominator.inverse().expect("indices should be distinct");
    }

    result
}
/// Verify a threshold signature against a message and verification key
pub fn verify_signature<E: Pairing>(
    vk: &VerificationKey<E>,
    message_commitments: &[SymmetricCommitment<E>],
    signature: &ThresholdSignature<E>,
) -> bool {
    // Pseudocode for verification:
    // assert e(σ, g̃) = e(h, g̃ᵡ) · ∏ₖ∈[ℓ] e(cmₖ, g̃ʸᵏ)

    // This is just a skeleton - implement the actual pairing check
    // based on your signature scheme
    true
}
