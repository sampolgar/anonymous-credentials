use crate::publicparams::PublicParams;
use ark_bls12_381::G1Affine;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct VerificationKey<E: Pairing> {
    pub vk: E::G1Affine,
}

pub struct SecretKey<E: Pairing> {
    pub sk: E::G2Affine,
}

pub struct KeyPair<E: Pairing> {
    pub vk: VerificationKey<E>,
    pub sk: SecretKey<E>,
}

impl<E: Pairing> KeyPair<E> {
    pub fn keygen(pp: &PublicParams<E>, rng: &mut impl Rng) -> Self {
        // Generate random scalar x
        let x = E::ScalarField::rand(rng);

        // Compute vk = g1^x
        let vk = pp.g1.mul(x).into_affine();

        // Compute sk = g2^x
        let sk = pp.g2.mul(x).into_affine();

        KeyPair {
            vk: VerificationKey { vk },
            sk: SecretKey { sk },
        }
    }
}

// Add test module
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn test_keygen() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&n, &mut rng);
        let keypair = KeyPair::keygen(&pp, &mut rng);
        let p1 = Pairing::<Bls12_381>::pairing(pp.g1, keypair.sk);
        let p2 = Pairing::<Bls12_381>::pairing(keypair.vk, pp.g2);

        // You can add additional tests here to verify the relationship between vk and sk
        // For example, you could verify that e(vk, g2) = e(g1, sk) if needed
    }
}
