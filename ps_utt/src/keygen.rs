use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct SecretKey<E: Pairing> {
    pub sk: E::G1Affine,
}
pub struct VerificationKey<E: Pairing> {
    pub vk: E::G2Affine,
}

pub struct SecretKeyImproved<E: Pairing> {
    pub sk: E::G2Affine,
}
pub struct VerificationKeyImproved<E: Pairing> {
    pub vk: E::G1Affine,
}

pub fn gen_keys<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKey<E>, VerificationKey<E>) {
    let x = E::ScalarField::rand(rng);
    let sk = pp.g1.mul(x).into_affine();
    let vk = pp.g2.mul(x).into_affine();
    (SecretKey { sk }, VerificationKey { vk })
}

pub fn gen_keys_improved<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKeyImproved<E>, VerificationKeyImproved<E>) {
    let x = E::ScalarField::rand(rng);
    let sk = pp.g2.mul(x).into_affine();
    let vk = pp.g1.mul(x).into_affine();
    (SecretKeyImproved { sk }, VerificationKeyImproved { vk })
}

// Add test module
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_keygen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (sk, vk) = gen_keys(&pp, &mut rng);

        let p1 = Bls12_381::pairing(pp.g1, vk.vk);
        let p2 = Bls12_381::pairing(sk.sk, pp.g2);
        assert_eq!(p1, p2, "p1 and p2 aren't equal!");
    }

    #[test]
    fn test_keygen_improved() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (sk, vk) = gen_keys_improved(&pp, &mut rng);

        let p1 = Bls12_381::pairing(vk.vk, pp.g2);
        let p2 = Bls12_381::pairing(pp.g1, sk.sk);
        assert_eq!(p1, p2, "p1 and p2 aren't equal!");
    }
}
