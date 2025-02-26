use crate::keygen::{self, PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use utils::pairing::PairingCheck;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusSignature<E: Pairing> {
    pub A: E::G1Affine,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusRandomizedSignature<E: Pairing> {
    pub A_prime: E::G1Affine,
    pub A_bar: E::G1Affine,
    pub d: E::G1Affine,
    pub e: E::ScalarField,
    pub s_prime: E::ScalarField,
    pub r1: E::ScalarField,
    pub r2: E::ScalarField,
    pub r3: E::ScalarField,
}

impl<E: Pairing> BBSPlusSignature<E> {
    // (A \gets pp.g1 . h_0^s . himi)^1/e+x
    pub fn sign(
        pp: &PublicParams<E>,
        sk: &SecretKey<E>,
        pk: &PublicKey<E>,
        rng: &mut impl Rng,
        messages: &Vec<E::ScalarField>,
    ) -> Self {
        let e = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);
        let himi: E::G1 = E::G1::msm(&pk.h1hL, &messages).unwrap();
        let b = pp.g1 + (pk.h0 * s + himi);
        let invexp = (sk.x + e).inverse().unwrap();
        let A = (b * invexp).into_affine();
        Self { A, e, s }
    }

    pub fn rerandomize<R: Rng>(
        &self,
        pp: &PublicParams<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> BBSPlusRandomizedSignature<E> {
        BBSPlusRandomizedSignature::randomize(self, &pp, &pk, &messages, rng)
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
    ) -> bool {
        assert_eq!(messages.len(), pk.h1hL.len(), "Invalid number of messages");

        let himi: E::G1 = E::G1::msm(&pk.h1hL, messages).unwrap();
        let b = pp.g1 + pk.h0 * self.s + himi;

        let lhs = E::pairing(self.A, pk.w + pp.g2.mul(self.e));
        let rhs = E::pairing(b.into_affine(), pp.g2);

        lhs == rhs
    }
}

impl<E: Pairing> BBSPlusRandomizedSignature<E> {
    pub(crate) fn randomize<R: Rng>(
        signature: &BBSPlusSignature<E>,
        pp: &PublicParams<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Self {
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        let A_prime = signature.A.mul(r1).into_affine();
        let himi: E::G1 = E::G1::msm(&pk.h1hL, messages).unwrap();
        let b = pp.g1 + pk.h0 * signature.s + himi;
        let A_bar = A_prime.mul(signature.e.neg()).add(b.mul(r1));

        let d = (b * r1) + (pk.h0 * r2.neg());

        let s_prime = signature.s - (r2 * r3);

        Self {
            A_prime,
            A_bar: A_bar.into_affine(),
            d: d.into_affine(),
            e: signature.e,
            s_prime,
            r1,
            r2,
            r3,
        }
    }

    pub fn verify_pairing(&self, pp: &PublicParams<E>, pk: &keygen::PublicKey<E>) -> bool {
        let lhs = E::pairing(self.A_prime, pk.w);
        let rhs = E::pairing(self.A_bar, pp.g2);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use crate::keygen;

    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_sign_and_verify() {
        let L = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&L, &context, &mut rng);
        let (sk, pk) = keygen::gen_keys::<Bls12_381>(&pp, &mut rng);

        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..L)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let signature = BBSPlusSignature::sign(&pp, &sk, &pk, &mut rng, &messages);
        let is_valid = signature.verify(&pp, &pk, &messages);
        assert!(is_valid, "Signature verification failed");

        let randomized_signature = signature.rerandomize(&pp, &pk, &messages, &mut rng);
        assert!(
            randomized_signature.verify_pairing(&pp, &pk),
            "Randomized signature verification failed"
        );
    }
}
