use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone)]
pub struct PublicParams<E: Pairing> {
    pub n: usize,
    pub g: E::G1Affine,
    pub g_tilde: E::G2Affine,
    pub ck: Vec<E::G1Affine>,
    pub ck_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(n: &usize, rng: &mut impl Rng) -> Self {
        let g = E::G1Affine::rand(rng);
        let g_tilde = E::G2Affine::rand(rng);

        let yi = (0..*n)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let ck = yi.iter().map(|yi| g.mul(*yi)).collect::<Vec<_>>();
        let ck = E::G1::normalize_batch(&ck);

        let ck_tilde = yi.iter().map(|yi| g_tilde.mul(*yi)).collect::<Vec<_>>();
        let ck_tilde = E::G2::normalize_batch(&ck_tilde);
        PublicParams {
            n: *n,
            g,
            g_tilde,
            ck,
            ck_tilde,
        }
    }

    /// returns g_1,...,g_n,h
    pub fn get_g1_bases(&self) -> Vec<&E::G1Affine> {
        self.ck.iter().chain(std::iter::once(&self.g)).collect()
    }

    pub fn get_g_tilde_bases(&self) -> Vec<&E::G2Affine> {
        self.ck_tilde
            .iter()
            .chain(std::iter::once(&self.g_tilde))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    #[test]
    fn test_pp_gen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&n, &mut rng);

        assert_eq!(pp.ck.len(), n, "ck length should match n");
        assert_eq!(pp.ck_tilde.len(), n, "ck_tilde length should match n");
        assert_eq!(pp.get_g1_bases().len(), n + 1, "g1 bases should include g");
    }
}
