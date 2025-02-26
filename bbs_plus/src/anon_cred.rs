// Obtain
// Issue
// Show
// Verify
use crate::keygen::{PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use utils::pairing::PairingCheck;
pub struct AnonCredProtocol;

impl AnonCredProtocol {

    // run by user, rerandomizes signature, generates proofs
    // takes in signature, messages
    pub fn show<E: Pairing, R: Rng>(
        &PublicParams,
        &PublicKey,

    )

    // run by verifier, inputs pk, proofs, outputs 1/0
    // pub fn verify<>()
}
