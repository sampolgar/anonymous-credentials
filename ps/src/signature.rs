use crate::keygen;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    One,
};
use utils::helpers::Helpers;

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    pub fn blind_sign<R: Rng>(
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        signature_commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pk.g1.mul(u).into_affine();
        let sigma2 = (pk.g1.mul(sk.x) + signature_commitment)
            .mul(u)
            .into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn unblind(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1,
            sigma2: (self.sigma2.into_group() - self.sigma1.mul(*t)).into_affine(),
        }
    }

    // rerandomize signature by scalar
    pub fn rerandomize(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(t).into_affine(),
            sigma2: self.sigma2.mul(t).into_affine(),
        }
    }

    //
    pub fn randomize_for_pok(&self, r: &E::ScalarField, t: &E::ScalarField) -> Self {
        let sigma1_temp = self.sigma1;
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: (self.sigma2.into_group() + sigma1_temp.mul(*t))
                .mul(r)
                .into_affine(),
        }
    }

    //
    pub fn randomize_for_pok_new<R: Rng>(&self, rng: &mut R, t: &E::ScalarField) -> Self {
        let sigma1_temp = self.sigma1;
        let r = E::ScalarField::rand(rng);
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: (self.sigma2.into_group() + sigma1_temp.mul(*t))
                .mul(r)
                .into_affine(),
        }
    }

    pub fn generate_commitment_gt(&self, pk: &keygen::PublicKey<E>) -> PairingOutput<E> {
        let signature_commitment_gt = Helpers::compute_gt::<E>(
            &[self.sigma2, self.sigma1.into_group().neg().into_affine()],
            &[pk.g2, pk.x_g2],
        );
        signature_commitment_gt
    }

    // this is for testing, public signature isn't used in anonymous credentials
    // this will be used for pairing testing
    pub fn public_sign(
        messages: &[E::ScalarField],
        sk: &keygen::SecretKey<E>,
        h: &E::G1Affine,
    ) -> Self {
        assert!(messages.len() == sk.yi.len());
        let mut exponent = sk.x;
        for (y, m) in sk.yi.iter().zip(messages.iter()) {
            exponent += *y * m;
        }
        let sigma2 = h.mul(exponent).into_affine();
        Self { sigma1: *h, sigma2 }
    }

    pub fn public_verify(&self, messages: &[E::ScalarField], pk: &keygen::PublicKey<E>) -> bool {
        assert!(!self.sigma1.is_zero());
        assert_eq!(pk.y_g1.len(), messages.len());

        let x_g2 = pk.x_g2.into_group();
        let yi = pk.y_g2.clone();
        let yimi = E::G2::msm(&yi, messages).unwrap();
        let yimix = yimi + x_g2;

        let a = E::G1Prepared::from(self.sigma1);
        let b = E::G2Prepared::from(yimix);
        let sigma2_inv = self.sigma2.into_group().neg();
        let c = E::G1Prepared::from(sigma2_inv);
        let d = E::G2Prepared::from(pk.g2);

        let multi_pairing = E::multi_pairing([a, c], [b, d]);
        multi_pairing.0.is_one()
    }
}

#[cfg(feature = "parallel")]
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::{Fr, G1Affine};

    #[test]
    fn test_sign_and_verify() {
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.sk;
        let pk = key_pair.pk;

        // Create messages
        let messages: Vec<Fr> = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let h = G1Affine::rand(&mut rng);
        let public_signature = Signature::<Bls12_381>::public_sign(&messages, &sk, &h);
        let is_valid = public_signature.public_verify(&messages, &pk);
        assert!(is_valid, "Public signature verification failed");
    }
}
