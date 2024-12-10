use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::RngCore;

#[derive(Clone)]
pub struct PublicParams<E: Pairing> {
    pub n: usize,
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub ckg1: Vec<E::G1Affine>,
    pub ckg2: Vec<E::G2Affine>,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(n: &usize, rng: &mut impl RngCore) -> Self {
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G2Affine::rand(rng);

        let yi = (0..*n)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let ckg1 = yi.iter().map(|yi| g1.mul(*yi)).collect::<Vec<_>>();
        let ckg1 = E::G1::normalize_batch(&ckg1);

        let ckg2 = yi.iter().map(|yi| g2.mul(*yi)).collect::<Vec<_>>();
        let ckg2 = E::G2::normalize_batch(&ckg2);
        PublicParams {
            n: *n,
            g1,
            g2,
            ckg1,
            ckg2,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;
    #[test]
    fn test_pp_gen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&n, &mut rng);
    }
}
