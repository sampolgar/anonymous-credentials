use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub x: E::ScalarField,
    pub yi: Vec<E::ScalarField>,
    pub x_g1: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub y_g1: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    pub y_g2: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
    pub x_g2: E::G2Affine,      //X_2 public key
}

#[derive(Clone, Debug)]
pub struct KeyPair<E: Pairing> {
    pub sk: SecretKey<E>,
    pub pk: PublicKey<E>,
}

pub fn gen_keys<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKey<E>, PublicKey<E>) {
    // setup random g points for the public key
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    // generate x and yi for each message
    // Generate x and y_i for each message
    let x = E::ScalarField::rand(rng);
    let yi = (0..pp.n)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = g1.mul(x).into_affine();
    let y_g1 = yi.iter().map(|yi| g1.mul(*yi)).collect::<Vec<_>>();
    let y_g1 = E::G1::normalize_batch(&y_g1);

    let x_g2 = g2.mul(x).into_affine();
    let y_g2 = yi.iter().map(|yi| g2.mul(*yi)).collect::<Vec<_>>();
    let y_g2 = E::G2::normalize_batch(&y_g2);

    let sk = SecretKey { x, yi, x_g1 };
    let pk = PublicKey { y_g1, y_g2, x_g2 };
    (sk, pk)
}

#[cfg(test)]
mod test {
    use super::*;
    // use crate::{gen_keys, PublicKey, SecretKey};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;
    use ark_std::rand::Rng;
    use ark_std::test_rng;

    #[test]
    fn test_key_generation_basic() {
        // Initialize test environment
        let mut rng = test_rng();
        let n = 3; // Support for 3 messages
        let context = Fr::rand(&mut rng);

        // Generate public parameters
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);

        // Generate a keypair
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Basic validation checks
        assert_eq!(sk.yi.len(), n, "Secret key should have n elements");
        assert_eq!(pk.y_g1.len(), n, "Public key G1 elements should match n");
        assert_eq!(pk.y_g2.len(), n, "Public key G2 elements should match n");

        // Verify the public parameters were properly used
        // assert_eq!(pk.g1, pp.g1, "Public key should use pp.g1");
        // assert_eq!(pk.g2, pp.g2, "Public key should use pp.g2");

        // Verify secret and public keys are related correctly
        for i in 0..n {
            let pairing1 = Bls12_381::pairing(pk.y_g1[i], pp.g2);
            let pairing2 = Bls12_381::pairing(pp.g1, pk.y_g2[i]);
            assert_eq!(pairing1, pairing2, "Pairing consistency check failed");
        }
    }
}
