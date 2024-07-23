use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::{PrimeField, UniformRand};
use ark_std::{rand::Rng, One}; //or here? UniformRand
use std::ops::{Add, Mul}; //do I use this
                          // pub struct Setup
                          // struct should take in a number - # of messages. Output Vector of scalars length of r + 1: x,y1_bases,..yr \gets Zp^{r+1}

struct SignatureParams<E: Pairing> {
    sig_g1: E::G1Affine,
    sig_g2: E::G2Affine,
    h_g1: Vec<E::G1Affine>,
}

struct SecretKey<F: PrimeField> {
    x: F,
    y: Vec<F>,
}

struct PublicKey<E: Pairing> {
    x_g2: E::G2Affine,
    y_g2: Vec<E::G2Affine>,
}

fn simple_setup<E: Pairing, R: Rng>(
    rng: &mut R,
    message_length: usize,
) -> (SecretKey<E::ScalarField>, PublicKey<E>, SignatureParams<E>) {
    // generate sig params
    let sig_g1 = E::G1Affine::rand(rng);
    let sig_g2 = E::G2Affine::rand(rng);
    let h_g1: Vec<E::G1Affine> = (0..message_length)
        .map(|_| E::G1Affine::rand(rng))
        .collect();
    let params = SignatureParams {
        sig_g1,
        sig_g2,
        h_g1,
    };

    // generate secret key
    let x = E::ScalarField::rand(rng);
    let y: Vec<E::ScalarField> = (0..message_length)
        .map(|_| E::ScalarField::rand(rng))
        .collect();
    let sk = SecretKey { x, y: y.clone() };

    // generate public key
    let x_g2 = E::G2::generator().mul(x).into_affine();
    let y_g2: Vec<E::G2Affine> = y
        .iter()
        .map(|yi| E::G2::generator().mul(yi).into_affine())
        .collect();
    let pk = PublicKey { x_g2, y_g2 };

    (sk, pk, params)
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
        let num_messages = 5;

        let witnesses: Vec<Fr> = (0..num_messages).map(|_| Fr::rand(&mut rng)).collect();

        let keygen = KeyGen::<Bls12_381>::new(&mut rng, num_messages);
        let bases = keygen.pk.ck_g1.clone();

        // y1*m1 + y2*m2 + ... + yr*mr
        let yi_mi = G1Projective::msm_unchecked(&bases, &witnesses).into_affine();
        // prover needs t s.t.  C = g^t yi_mi

        let commitment = SchnorrProtocol::commit(&bases, &mut rng);
        //
        let challenge = Fr::rand(&mut rng);
        let proofs = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        let is_valid = SchnorrProtocol::verify(&bases, &yi_mi, &commitment, &proofs, &challenge);
        assert!(is_valid)
    }
}
