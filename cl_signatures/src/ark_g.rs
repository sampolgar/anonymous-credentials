use ark_ec::{AdditiveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField};
use ark_std::{ops::Mul, UniformRand, Zero};
use bls12_381::{Fr as ScalarField, G1Projective as G};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group() {
        let mut rng = ark_std::test_rng();
        let a = G::rand(&mut rng);
        let b = G::rand(&mut rng);
        println!("{:?}, {:?}", a, b);
        let c = a + b;
        println!("{:?}", c);
    }
}
