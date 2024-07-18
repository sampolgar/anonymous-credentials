use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::UniformRand;
use std::ops::{Add, Mul};

type G1A = G1Affine;
type G2A = G2Affine;

struct SecretKey {
    x: Fr,
    y: Fr,
}

struct PublicKey {
    x: G2A,
    y: G2A,
}

struct Signature {
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

fn keygen() -> (SecretKey, PublicKey) {
    let mut rng = ark_std::test_rng();
    let g2 = g2_generator();

    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);

    let sk = SecretKey { x, y };
    let pk = PublicKey {
        x: g2.mul(x).into_affine(),
        y: g2.mul(y).into_affine(),
    };

    (sk, pk)
}

// sk in Fp, pk in g2, Signature in g1
// sigma_2 = h^x+y*m
// h.mul(sk.x.into_repr()).add(&g1.mul(sk.y.into_repr()).mul(message.into_repr()));
fn sign(sk: &SecretKey, message: &Fr) -> Signature {
    let mut rng = ark_std::test_rng();
    let h = G1A::rand(&mut rng);

    let sigma_1 = h;
    let x = sk.x;
    let y = sk.y;
    let exponent = x + y * message;
    let sigma_2 = h.mul(exponent).into_affine();
    Signature { sigma_1, sigma_2 }
}

fn rerandomize(signature: &Signature) -> Signature {
    let mut rng = ark_std::test_rng();
    let t = Fr::rand(&mut rng);

    Signature {
        sigma_1: signature.sigma_1.mul(t).into_affine(),
        sigma_2: signature.sigma_2.mul(t).into_affine(),
    }
}

// e(sigma_1, pk.x, pk.y ^m) = e(sigma_2, g_tilde)
fn verify(pk: &PublicKey, message: &Fr, signature: &Signature) -> bool {
    let g2 = g2_generator();

    let lhs_2 = pk.y.mul(message).add(pk.x).into_affine();

    compare_pairings(&signature.sigma_1, &lhs_2, &signature.sigma_2, &g2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps1() {
        let (sk, pk) = keygen();
        let mut rng = ark_std::test_rng();

        let message = Fr::rand(&mut rng);
        let signature = sign(&sk, &message);
        let is_valid = verify(&pk, &message, &signature);
        println!("Signature validity: {}", is_valid);
    }

    #[test]
    fn test_ps1_rerand() {
        let (sk, pk) = keygen();
        let mut rng = ark_std::test_rng();

        let message = Fr::rand(&mut rng);
        let signature = sign(&sk, &message);
        let rerand_signature = rerandomize(&signature);
        let is_valid = verify(&pk, &message, &rerand_signature);
        println!("Signature validity: {}", is_valid);
    }
}
