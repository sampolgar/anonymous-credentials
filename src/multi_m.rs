use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use ark_std::{UniformRand, Zero};
use std::ops::{Add, Mul};

type G1A = G1Affine;
type G2A = G2Affine;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey {
    x: Fr,
    y: Vec<Fr>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey {
    x_tilde: G2A,
    y_tilde: Vec<G2A>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature {
    sigma_1: G1A,
    sigma_2: G1A,
}

pub fn compare_pairings(g1_1: &G1A, g2_1: &G2A, g1_2: &G1A, g2_2: &G2A) -> bool {
    let pairing1 = Bls12_381::pairing(g1_1, g2_1);
    let pairing2 = Bls12_381::pairing(g1_2, g2_2);
    pairing1 == pairing2
}

// Function to get the G1 generator
pub fn g1_generator() -> G1A {
    G1A::generator()
}

// Function to get the G2 generator
pub fn g2_generator() -> G2A {
    G2A::generator()
}

pub fn keygen<R: ark_std::rand::Rng>(
    rng: &mut R,
    attribute_count: usize,
) -> (SecretKey, PublicKey) {
    let g2 = g2_generator();

    let x = Fr::rand(rng);
    let y: Vec<Fr> = (0..attribute_count).map(|_| Fr::rand(rng)).collect();

    let sk = SecretKey { x, y: y.clone() };
    let pk = PublicKey {
        x_tilde: g2.mul(x).into_affine(),
        y_tilde: y.iter().map(|yi| g2.mul(yi).into_affine()).collect(),
    };

    (sk, pk)
}

pub fn sign<R: ark_std::rand::Rng>(sk: &SecretKey, messages: &[Fr], rng: &mut R) -> Signature {
    assert_eq!(messages.len(), sk.y.len(), "invalid number of messages");

    let h = G1A::rand(rng);
    let g1 = g1_generator();

    let mut exponent = sk.x;
    for (yi, mi) in sk.y.iter().zip(messages.iter()) {
        exponent += *yi * mi;
    }

    Signature {
        sigma_1: h,
        sigma_2: h.mul(exponent).into_affine(),
    }
}

pub fn verify(pk: &PublicKey, messages: &[Fr], signature: &Signature) -> bool {
    assert_eq!(
        messages.len(),
        pk.y_tilde.len(),
        "invalid number of messages to pk.y length"
    );

    let g2 = g2_generator();

    let mut x_plus_ym = pk.x_tilde;
    for (y_tilde_i, m_i) in pk.y_tilde.iter().zip(messages.iter()) {
        x_plus_ym = x_plus_ym.add(y_tilde_i.mul(*m_i)).into_affine();
    }
    compare_pairings(&signature.sigma_1, &x_plus_ym, &signature.sigma_2, &g2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_messages<R: ark_std::rand::Rng>(rng: &mut R, count: usize) -> Vec<Fr> {
        (0..count).map(|_| Fr::rand(rng)).collect()
    }

    // #[test]
    // fn test_keygen() {
    //     let mut rng = ark_std::test_rng();
    //     for attribute_count in [5, 10, 20] {
    //         let (sk, pk) = keygen(&mut rng, attribute_count);
    //         println!("keygen is valid with {} attributes", attribute_count);
    //     }
    // }

    // #[test]
    // fn test_sign() {
    //     let mut rng = ark_std::test_rng();
    //     for attribute_count in [5, 10, 20] {
    //         let (sk, pk) = keygen(&mut rng, attribute_count);
    //         let messages = random_messages(&mut rng, attribute_count);
    //         let signature = sign(&sk, &messages, &mut rng);
    //         println!("keygen is valid with {} attributes", attribute_count);
    //     }
    // }

    #[test]
    fn test_multiattribute_ps() {
        let mut rng = ark_std::test_rng();

        for attribute_count in [5, 10, 20] {
            let (sk, pk) = keygen(&mut rng, attribute_count);
            let messages = random_messages(&mut rng, attribute_count);
            let signature = sign(&sk, &messages, &mut rng);
            let is_valid = verify(&pk, &messages, &signature);
            assert!(
                is_valid,
                "Signature should be valid for {} attributes",
                attribute_count
            );
        }
    }
}

