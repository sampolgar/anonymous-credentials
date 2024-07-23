use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::UniformRand;
use ark_std::{rand::Rng, One}; //or here? UniformRand
use std::ops::{Add, Mul}; //do I use this
                          // pub struct Setup
                          // struct should take in a number - # of messages. Output Vector of scalars length of r + 1: x,y1_bases,..yr \gets Zp^{r+1}

pub struct SecretKey<E: Pairing> {
    x1: E::G1Affine,
}

pub struct PublicKey<E: Pairing> {
    g1: E::G1Affine,
    g2: E::G2Affine,
    y1_bases: Vec<E::G1Affine>,
    x2: E::G2Affine,
    y2_bases: Vec<E::G2Affine>,
}

pub struct KeyGen<E: Pairing> {
    pub x: E::ScalarField,
    pub y: Vec<E::ScalarField>,
    pub pk: PublicKey<E>,
    pub sk: SecretKey<E>,
}

impl<E: Pairing> KeyGen<E> {
    pub fn new<R: Rng>(rng: &mut R, num_messages: usize) -> Self {
        let g1 = E::G1::generator();
        let g2 = E::G2::generator();

        let x = E::ScalarField::rand(rng);
        let y: Vec<E::ScalarField> = (0..num_messages)
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        let sk = SecretKey {
            x1: g1.mul(&x).into_affine(),
        };

        let pk = PublicKey {
            g1: g1.into_affine(),
            g2: g2.into_affine(),
            x2: g2.mul(x).into_affine(),
            y1_bases: y.iter().map(|yi| g1.mul(yi).into_affine()).collect(),
            y2_bases: y.iter().map(|yi| g2.mul(yi).into_affine()).collect(),
        };
        KeyGen { x, y, pk, sk }
    }
}

pub struct Signature<E: Pairing> {
    sigma_1: E::G1Affine,
    sigma_2: E::G1Affine,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::VariableBaseMSM;
    use ark_std::rand::RngCore;
    use ark_std::test_rng;

    #[test]
    fn test_current() {
        let mut rng = test_rng();
        let num_messages = 3;
        let witnesses: Vec<Fr> = (0..num_messages).map(|_| Fr::rand(&mut rng)).collect();

        let keygen = KeyGen::<Bls12_381>::new(&mut rng, num_messages);
        let bases = keygen.pk.y1_bases.clone();
        let public_commitment = G1Projective::msm_unchecked(&bases, &witnesses).into_affine();

        // prover generates things for protocol
        let commitment_prime = SchnorrProtocol::commit(&bases, &mut rng);
        let challenge = Fr::rand(&mut rng);
        let proofs = SchnorrProtocol::prove(&commitment_prime, &witnesses, &challenge);

        let is_valid = SchnorrProtocol::verify(
            &bases,
            &public_commitment,
            &commitment_prime,
            &proofs,
            &challenge,
        );
        assert!(is_valid)
    }
}
