use crate::commitment::Commitment;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;

#[derive(Clone, Debug)]
pub struct PSSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

pub struct VerificationKey<E: Pairing> {
    pub vk: E::G1Affine,
}

struct SecretKey<E: Pairing> {
    sk: E::G1Affine,
}

impl<E: Pairing> PSSignature<E> {
    
}
