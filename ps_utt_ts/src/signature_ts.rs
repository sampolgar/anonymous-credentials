// includes threshold_signature operations
//
use crate::commitment::{CommitmentError, SymmetricCommitment, SymmetricCommitmentKey};
use crate::dkg_keygen::{
    dkg_keygen, SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare,
};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One,
};
use thiserror::Error;
use utils::pairing::PairingCheck;

#[derive(Clone, Debug)]
pub struct PartialSignature<E: Pairing> {
    pub party_index: usize,
    pub sigma_2_i: E::G1Affine,
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

#[derive(Error, Debug)]
pub enum ThresholdSignatureError {
    #[error("Insufficient signature shares: needed {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },

    #[error("Invalid signature share from party {0}")]
    InvalidShare(usize),

    #[error("Inconsistent signature shares")]
    InconsistentShares,

    #[error("Invalid parameters")]
    InvalidParameters,

    #[error("Component not initialized")]
    NotInitialized,

    #[error("Commitment error: {0}")]
    CommitmentError(#[from] CommitmentError),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
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
    params: &PublicParams<E>,
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
