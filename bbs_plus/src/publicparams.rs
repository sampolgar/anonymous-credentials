use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct PublicParams<E: Pairing> {
    pub context: E::ScalarField, //e.g. Hash to Field(dmv)
    pub L: usize,
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(L: &usize, context: &E::ScalarField, rng: &mut impl Rng) -> Self {
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G2Affine::rand(rng);
        PublicParams {
            context: *context,
            L: *L,
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
        let L = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&L, &context, &mut rng);
    }
}
