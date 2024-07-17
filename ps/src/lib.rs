// use ark_bls12_381::{
//     g1::Config as G1A, g2::Config as G2A, Bls12_381, Fr, G1Projective as G1, G2Projective as G2,
// };
// use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig};

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::UniformRand;
// Type aliases for clarity
type G1A = G1Affine;
type G2A = G2Affine;

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

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use ark_bls12_381::g1;

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
}
