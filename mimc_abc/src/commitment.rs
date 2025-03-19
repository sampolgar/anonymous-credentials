use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::SchnorrProtocol;

pub struct Commitment<E: Pairing> {
    pub cm: E::G1Affine,
    pub cm_tilde: E::G2Affine,
}

pub struct CommitmentKey<E: Pairing> {
    pub ck: Vec<E::G1Affine>,
    pub ck_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> CommitmentKey<E> {
    pub fn commit(
        &self,
        pp: &PublicParams<E>,
        messages: &[E::ScalarField],
        r: &E::ScalarField,
    ) -> Commitment<E> {
        let cm = E::G1::msm_unchecked(&self.ck, messages)
            .add(pp.g.mul(r))
            .into_affine();
        let cm_tilde = E::G2::msm_unchecked(&self.ck_tilde, messages)
            .add(pp.g_tilde.mul(r))
            .into_affine();
        Commitment { cm, cm_tilde }
    }
}
