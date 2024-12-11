use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct KeyPair<E: Pairing> {
    pub sk: E::G1Affine,
    pub vk: E::G2Affine,
}

impl<E: Pairing> KeyPair<E> {
    pub fn keygen(pp: &PublicParams<E>, rng: &mut impl Rng) -> Self {
        // Generate random scalar x
        let x = E::ScalarField::rand(rng);

        // Compute vk = g1^x
        let vk = pp.g2.mul(x).into_affine();

        // Compute sk = g2^x
        let sk = pp.g1.mul(x).into_affine();

        KeyPair { sk, vk }
    }
}

// Add test module
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::PairingOutput;

    #[test]
    fn test_keygen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&n, &mut rng);
        let keypair = KeyPair::keygen(&pp, &mut rng);

        let p1 = Bls12_381::pairing(pp.g1, keypair.vk);
        let p2 = Bls12_381::pairing(keypair.sk, pp.g2);
        assert_eq!(p1, p2, "p1 and p2 aren't equal!");
    }
}
