use crate::publicparams::{self, PublicParams};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use utils::helpers::Helpers;

pub struct Commitment<E: Pairing> {
    pp: PublicParams<E>,
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
    cmg1: E::G1Affine,
    cmg2: E::G2Affine,
}

// takes in pp, messages, r. creates cmg1, cmg2 by 1. exponentiate each pp.ckg1 with mi and pp.g1 with r, msm together
//
// impl<E: Pairing> Commitment<E> {
//     pub fn new(pp: PublicParams<E>, messages::Vec<E::ScalarField>, r: E::ScalarField) -> Self{

//     }
// }

#[cfg(test)]
mod tests {}
