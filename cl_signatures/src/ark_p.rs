use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_std::UniformRand;

use ark_bls12_381::{Bls12_381, Fr as ScalarField, G1Projective as G1, G2Projective as G2};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing() {
        let mut rng = ark_std::test_rng();
        let s = ScalarField::rand(&mut rng);
        let a = G1::rand(&mut rng);
        let b = G2::rand(&mut rng);

        // monolithic pairing
        let e1 = Bls12_381::pairing(a, b);

        // Miller loop
        let ml_res = Bls12_381::miller_loop(a, b);
        let e2 = Bls12_381::final_exponentiation(ml_res).unwrap();
        assert_eq!(e1, e2);
    }
}
