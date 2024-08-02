use ark_bls12_381::{Bls12_381, Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::CyclotomicMultSubgroup;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::uint;
use ark_std::test_rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
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
    fn test_gt_points() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let s1 = Fr::one();
        let s2 = s1 + Fr::one();
        let s3 = s2 + Fr::one();
        let s4 = s3 + Fr::one();
        let s5 = s4 + Fr::one();
        let s6 = s5 + Fr::one();

        let gt1 = Bls12_381::pairing(g1.mul(s1), g2.mul(s4));
        let gt2 = Bls12_381::pairing(g1.mul(s2), g2.mul(s2));
        assert!(gt1 == gt2);

        let gt3 = Bls12_381::pairing(g1.mul(s1), g2.mul(s4));
        let gt4 = Bls12_381::pairing(g1.mul(s1), g2.mul(s2));
        assert!(gt3 == gt4 + gt4, "test 2");

        let gt5 = Bls12_381::pairing(g1.mul(s1), g2.mul(s6));
        let gt6 = Bls12_381::pairing(g1.mul(s2), g2.mul(s3));
        // e(1,6) = e(2,3)
        assert!(gt5 == gt6, "test 3");

        // e(1,4) + e(1,2) = e(1,6)
        assert!(gt3 + gt4 == gt5, "test 4");

        // e(1,2)^3 = e(1,6)
        let s3_big_int = s3.into_bigint();
        let gt7 = gt4.mul_bigint(s3_big_int);
        assert!(gt7 == gt5, "test 5");

        // e(1,6) - e(1,2) = e(1,4) - can't divide
        let gt8 = Bls12_381::pairing(g1.mul(s1), g2.mul(s3));
        assert!(gt5 - gt4 == gt3, "gt5 - gt4 == gt3");

        // e(1,6) - e(1,2) = e(1,4)
    }
}
