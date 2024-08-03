use crate::keygen;
use schnorr::schnorr::SchnorrProtocol;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use rayon::prelude::*;

#[derive(Clone, Debug)]
struct Signature<E: Pairing> {
    sigma1: E::G1Affine,
    sigma2: E::G1Affine,
}

