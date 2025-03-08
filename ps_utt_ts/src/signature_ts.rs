use crate::commitment::{Commitment, CommitmentError, CommitmentKey};
use crate::dkg_keygen::{
    dkg_keygen, SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare,
};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One,
};
use thiserror::Error;
use utils::pairing::PairingCheck;

// #[derive(Clone, Debug)]
// pub struct PartialSignature<E: Pairing> {
//     pub party_index: usize,
//     pub sigma_2_i: E::G1Affine,
// }

// #[derive(Clone, Debug)]
// pub struct Signature<E: Pairing> {
//     pub sigma1: E::G2Affine,
//     pub sigma2: E::G2Affine,
// }

// impl<E: Pairing> Signature<E> {}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     use ark_bls12_381::{Bls12_381, Fr};
// }

// pub struct SignatureShare<E: Pairing> {
//     pub index: usize,
//     pub h: E::G1Affine,
//     pub sigma: E::G1Affine,
// }

// pub struct BlindSignature<E: Pairing> {
//     pub h: E::G1Affine,
//     pub sigma: E::G1Affine,
// }

#[derive(Error, Debug)]
pub enum ThresholdSignatureError {
    #[error("Insufficient signature shares")]
    InsufficientShares,
    #[error("Invalid signature share")]
    InvalidShare,
}

// // Utility function for Lagrange coefficient calculation
// // (Used by both aggregation and potentially verification)
// pub fn compute_lagrange_coefficient<E: Pairing>(indices: &[usize], j: usize) -> E::ScalarField {
//     // Implementation
// }
// Blind signature received from signers
pub struct BlindSignature<E: Pairing> {
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

// Signature share from an individual signer
pub struct SignatureShare<E: Pairing> {
    pub index: usize,
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}
