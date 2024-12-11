use crate::commitment::Commitment;
use crate::keygen::KeyPair;
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

impl<E: Pairing> PSSignature<E> {
    pub fn blind_sign<R: Rng>(
        pp: &PublicParams<E>,
        keypair: &KeyPair<E>,
        commitment: &Commitment<E>,
        rng: &mut impl Rng,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g1.mul(u).into_affine();
        let sigma2 = (commitment.cmg1.add(keypair.sk)).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn rerandomize<R: Rng>(
        pp: &PublicParams<E>,
        
    )
}
