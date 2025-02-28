use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct PublicParams<E: Pairing> {
    pub context: E::ScalarField, // Domain separation value
    pub n: usize,                // Number of supported messages
    pub g1: E::G1Affine,         // Base generator for G1
    pub g2: E::G2Affine,         // Base generator for G2
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(n: &usize, context: &E::ScalarField, rng: &mut impl Rng) -> Self {
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G2Affine::rand(rng);

        PublicParams {
            context: *context,
            n: *n,
            g1,
            g2,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_pp_gen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);

        // Verify the public parameters were created
        assert!(!pp.g1.is_zero(), "g1 should not be the identity");
        assert!(!pp.g2.is_zero(), "g2 should not be the identity");
        assert_eq!(pp.n, n, "Message count should match");
    }
}
