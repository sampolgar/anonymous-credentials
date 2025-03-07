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
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::Pairing;

    pub fn test_thing<P: Pairing>(l: usize) {
        // test the commitment algorithm from
        let mut rng = test_rng();
        let g1_rand = G1Affine::rand(&mut rng);
        let g2_rand = G2Affine::rand(&mut rng);

        let y1 = Fr::rand(&mut rng);
        let y2 = Fr::rand(&mut rng);
        let y3 = Fr::rand(&mut rng);
        let y4 = Fr::rand(&mut rng);

        let g1_1 = g1_rand.mul(y1);
        let g1_2 = g1_rand.mul(y2);
        let g1_3 = g1_rand.mul(y3);
        let g1_4 = g1_rand.mul(y4);
        let g2_1 = g2_rand.mul(y1);
        let g2_2 = g2_rand.mul(y2);
        let g2_3 = g2_rand.mul(y3);
        let g2_4 = g2_rand.mul(y4);

        let m1 = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);

        let lhs = compute_gt::<Bls12_381>(&[g1_1.into_affine()], &[g2_4.into_affine()]);
        let rhs = compute_gt::<Bls12_381>(&[g1_4.into_affine()], &[g2_1.into_affine()]);
        assert_eq!(lhs, rhs, "lhs, rhs neq");
        println!("lhs eq rhs");

        let cmg1 = g1_1.mul(m1) + g1_rand.mul(r);
        let cmg2 = g2_1.mul(m1) + g2_rand.mul(r);
        let lhs1 = compute_gt::<Bls12_381>(&[cmg1.into_affine()], &[g2_rand]);
        let rhs1 = compute_gt::<Bls12_381>(&[g1_rand], &[cmg2.into_affine()]);
        assert_eq!(lhs1, rhs1, "lhs1, rhs1 neq");
        println!("lhs1 eq rhs1");

        // gen commitment.
    }

    pub fn compute_gt<E: Pairing>(
        g1_points: &[E::G1Affine],
        g2_points: &[E::G2Affine],
    ) -> PairingOutput<E> {
        assert_eq!(
            g1_points.len(),
            g2_points.len(),
            "Mismatched number of G1 and G2 points"
        );

        // Prepare points for pairing
        let prepared_g1: Vec<_> = g1_points.iter().map(E::G1Prepared::from).collect();
        let prepared_g2: Vec<_> = g2_points.iter().map(E::G2Prepared::from).collect();

        // Compute and return the multi-pairing
        E::multi_pairing(prepared_g1, prepared_g2)
    }

    #[test]
    pub fn test_this_thing() {
        test_thing::<Bls12_381>(4);
    }
}
