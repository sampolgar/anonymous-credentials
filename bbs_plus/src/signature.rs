use crate::keygen::{PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use utils::pairing::PairingCheck;

#[derive(Clone, Debug)]
pub struct BBSPlusSignature<E: Pairing> {
    pub A: E::G1Affine,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
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
        let h0mL = pk.get_h1_to_hL();
        let h1m1: E::G1 = E::G1::msm(&h0mL, &messages).unwrap();
        let b = pp.g1 + (pk.get_h0() * s + h1m1);
        let invexp = (sk.x + e).inverse().unwrap();
        let A = (b * invexp).into_affine();
        Self { A, e, s }
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
    ) -> bool {
        let h1_hL = pk.get_h1_to_hL();
        assert_eq!(messages.len(), h1_hL.len(), "Invalid number of messages");

        let himi: E::G1 = E::G1::msm(&h1_hL, messages).unwrap();
        let b = pp.g1 + pk.get_h0() * self.s + himi;

        let lhs = E::pairing(self.A, pk.w + pp.g2.mul(self.e));
        let rhs = E::pairing(b.into_affine(), pp.g2);

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
    }
}
