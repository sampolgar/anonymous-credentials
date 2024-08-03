use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
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
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub y_g1: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    pub y_g2: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
    pub x_g2: E::G2Affine,      //X_2 public key
}

#[derive(Clone, Debug)]
pub struct KeyPair<E: Pairing> {
    pub sk: SecretKey<E>,
    pub pk: PublicKey<E>,
}

pub fn keygen<E: Pairing, R: Rng>(rng: &mut R, message_count: &usize) -> KeyPair<E> {
    // setup random g points for the public key
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    // generate x and yi for each message
    // Generate x and y_i for each message
    let x = E::ScalarField::rand(rng);
    let yi = (0..*message_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = g1.mul(x).into_affine();
    let y_g1 = yi.iter().map(|yi| g1.mul(*yi)).collect::<Vec<_>>();
    let y_g1 = E::G1::normalize_batch(&y_g1);

    let x_g2 = g2.mul(x).into_affine();
    let y_g2 = yi.iter().map(|yi| g2.mul(*yi)).collect::<Vec<_>>();
    let y_g2 = E::G2::normalize_batch(&y_g2);

    KeyPair {
        sk: SecretKey { x, yi, x_g1 },
        pk: PublicKey {
            g1,
            g2,
            y_g1,
            y_g2,
            x_g2,
        },
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

#[cfg(feature = "parallel")]
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

        // Check that the correct number of y values were generated
        assert_eq!(key_pair.sk.yi.len(), message_count);
        assert_eq!(key_pair.pk.y_g1.len(), message_count);
        assert_eq!(key_pair.pk.y_g2.len(), message_count);

        // Verify that x_g1 and x_g2 are correctly computed
        assert_eq!(
            key_pair.pk.g1.mul(key_pair.sk.x).into_affine(),
            key_pair.sk.x_g1
        );
        assert_eq!(
            key_pair.pk.g2.mul(key_pair.sk.x).into_affine(),
            key_pair.pk.x_g2
        );

        // Verify that y_g1 and y_g2 are correctly computed
        for i in 0..message_count {
            assert_eq!(
                key_pair.pk.g1.mul(key_pair.sk.yi[i]).into_affine(),
                key_pair.pk.y_g1[i]
            );
            assert_eq!(
                key_pair.pk.g2.mul(key_pair.sk.yi[i]).into_affine(),
                key_pair.pk.y_g2[i]
            );
        }
    }

    #[test]
    fn test_keygen_with_6_messages() {
        let mut rng = test_rng();
        let message_count = 6;
        let key_pair = keygen::<Bls12_381, _>(&mut rng, &message_count);

        // Check that the correct number of y values were generated
        assert_eq!(key_pair.sk.yi.len(), message_count);
        assert_eq!(key_pair.pk.y_g1.len(), message_count);
        assert_eq!(key_pair.pk.y_g2.len(), message_count);

        // Verify that x_g1 and x_g2 are correctly computed
        assert_eq!(
            key_pair.pk.g1.mul(key_pair.sk.x).into_affine(),
            key_pair.sk.x_g1
        );
        assert_eq!(
            key_pair.pk.g2.mul(key_pair.sk.x).into_affine(),
            key_pair.pk.x_g2
        );

        // Verify that y_g1 and y_g2 are correctly computed
        for i in 0..message_count {
            assert_eq!(
                key_pair.pk.g1.mul(key_pair.sk.yi[i]).into_affine(),
                key_pair.pk.y_g1[i]
            );
            assert_eq!(
                key_pair.pk.g2.mul(key_pair.sk.yi[i]).into_affine(),
                key_pair.pk.y_g2[i]
            );
        }
    }
}
