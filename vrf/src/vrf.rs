// https://github.com/docknetwork/crypto/blob/main/syra/src/vrf.rs#L84
// asymettric vrf

use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    CurveGroup,
};
// {AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_std::{ops::Mul, rand::Rng, sync::Mutex, One, UniformRand, Zero};
// use itertools::Itertools;
use rayon::prelude::*;
use std::ops::MulAssign;

// secret key sk s
// public key pk
// secret message x

// prove(sk, x) -> Fsk(x), π
// verify(x, y, π, pk)

#[derive(Clone, Debug)]
pub struct Secrets<E: Pairing> {
    pub s: E::ScalarField,
    pub x: E::ScalarField,
}

pub struct PublicKey<E: Pairing> {
    pub pk: E::G1Affine,
}

pub struct VRF;

impl<E: Pairing> VRF<E> {}
