mod testing;

use std::ops::{Add, Mul};

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::UniformRand;
// Type aliases for clarity
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

// e(sigma_1, pk.x, pk.y ^m) = e(sigma_2, g_tilde)
fn verify(pk: &PublicKey, message: &Fr, signature: &Signature) -> bool {
    let g1 = g1_generator();
    let g2 = g2_generator();

    let lhs_2 = pk.y.mul(message).add(pk.x).into_affine();

    compare_pairings(&signature.sigma_1, &lhs_2, &signature.sigma_2, &g2)
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use super::*;

    #[test]
    fn test_pairing_comparison() {
        let mut rng = ark_std::test_rng();

        // Generate random points
        let g1_1 = G1A::rand(&mut rng);
        let g2_1 = G2A::rand(&mut rng);
        let g1_2 = G1A::rand(&mut rng);
        let g2_2 = G2A::rand(&mut rng);

        // Test equality
        assert!(compare_pairings(&g1_1, &g2_1, &g1_1, &g2_1));

        // Test inequality
        assert!(!compare_pairings(&g1_1, &g2_1, &g1_2, &g2_2));
    }

    #[test]
    fn test_g1_g2_scalar() {
        let mut rng = ark_std::test_rng();
        let g1 = g1_generator();
        let g2 = g2_generator();

        let scalar1 = Fr::rand(&mut rng);
        let scalar2 = Fr::rand(&mut rng);

        let g1_mul1 = g1.mul(scalar1).into_affine();
        let g2_mul1 = g2.mul(scalar1).into_affine();

        let g1_mul2 = g1.mul(scalar2).into_affine();
        let g2_mul2 = g2.mul(scalar2).into_affine();

        let g2_mul1_2 = g2.mul(scalar1 * scalar2).into_affine();

        // Test pairing equality: e(a*G1, G2) = e(G1, a*G2)
        assert!(compare_pairings(&g1_mul1, &g2, &g1, &g2_mul1));

        // Test pairing equality: e(a*G1, b*G2) = e(G1, ab*G2)
        assert!(compare_pairings(&g1_mul1, &g2_mul2, &g1, &g2_mul1_2));
    }

    #[test]
    fn test_ps1() {
        let (sk, pk) = keygen();
        let mut rng = ark_std::test_rng();

        let message = Fr::rand(&mut rng);
        let signature = sign(&sk, &message);
        let is_valid = verify(&pk, &message, &signature);
        println!("Signature validity: {}", is_valid);
    }
}
