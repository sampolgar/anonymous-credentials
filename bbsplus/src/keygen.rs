use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub x: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub h0: E::G1Affine,
    pub h_l: Vec<E::G1Affine>, // [h_1, h_2, ..., h_L]
    pub w: E::G2Affine,        // g2^x
}

#[derive(Clone, Debug)]
pub struct KeyPair<E: Pairing> {
    pub sk: SecretKey<E>,
    pub pk: PublicKey<E>,
}

pub fn keygen<E: Pairing, R: Rng>(rng: &mut R, message_count: &usize) -> KeyPair<E> {
    // Generate random generators
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);
    let h0 = E::G1Affine::rand(rng);

    // Generate secret key
    let x = E::ScalarField::rand(rng);

    // Compute w = g2^x
    let w = g2.mul(x).into_affine();

    // Generate h values
    let h_l: Vec<E::G1Affine> = (0..*message_count)
        .map(|_| E::G1Affine::rand(rng))
        .collect();

    KeyPair {
        sk: SecretKey { x },
        pk: PublicKey { g1, g2, h0, h_l, w },
    }
}

impl<E: Pairing> KeyPair<E> {
    pub fn secret_key(&self) -> &SecretKey<E> {
        &self.sk
    }

    pub fn public_key(&self) -> &PublicKey<E> {
        &self.pk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_keygen_with_2_messages() {
        let mut rng = test_rng();
        let message_count = 2;
        let key_pair = keygen::<Bls12_381, _>(&mut rng, &message_count);

        // Check that the correct number of h values were generated
        assert_eq!(key_pair.pk.h_l.len(), message_count);

        // Verify that w is correctly computed
        assert_eq!(
            key_pair.pk.g2.mul(key_pair.sk.x).into_affine(),
            key_pair.pk.w
        );
    }

    #[test]
    fn test_keygen_with_6_messages() {
        let mut rng = test_rng();
        let message_count = 6;
        let key_pair = keygen::<Bls12_381, _>(&mut rng, &message_count);

        // Check that the correct number of h values were generated
        assert_eq!(key_pair.pk.h_l.len(), message_count);

        // Verify that w is correctly computed
        assert_eq!(
            key_pair.pk.g2.mul(key_pair.sk.x).into_affine(),
            key_pair.pk.w
        );
    }
}
