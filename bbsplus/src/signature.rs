use crate::bbsplusproofs::BBSPlusProofs;
use crate::keygen;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One,
};
use utils::helpers::Helpers;

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub a: E::G1Affine,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RandomizedSignature<E: Pairing> {
    pub a_prime: E::G1Affine,
    pub a_bar: E::G1Affine,
    pub d: E::G1Affine,
    pub e: E::ScalarField,
    pub s_prime: E::ScalarField,
    pub r1: E::ScalarField,
    pub r2: E::ScalarField,
    pub r3: E::ScalarField,
}

impl<E: Pairing> Signature<E> {
    pub fn blind_sign<R: Rng>(
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        signature_commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        let e = E::ScalarField::rand(rng);
        let s2 = E::ScalarField::rand(rng);
        let b = pk.g1 + pk.h0 * s2 + signature_commitment;
        let invexp = (sk.x + e).inverse().unwrap();
        let a = (b * invexp).into_affine();
        Self { a, e, s: s2 }
    }

    pub fn sign<R: Rng>(
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Self {
        assert_eq!(messages.len(), pk.h_l.len(), "Invalid number of messages");

        let e = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        let himi: E::G1 = E::G1::msm(&pk.h_l, messages).unwrap();
        let b = pk.g1 + pk.h0 * s + himi;

        let invexp = (sk.x + e).inverse().unwrap();
        let a = (b * invexp).into_affine();

        Self { a, e, s }
    }

    pub fn verify(&self, pk: &keygen::PublicKey<E>, messages: &[E::ScalarField]) -> bool {
        assert_eq!(messages.len(), pk.h_l.len(), "Invalid number of messages");

        let himi: E::G1 = E::G1::msm(&pk.h_l, messages).unwrap();
        let b = pk.g1 + pk.h0 * self.s + himi;

        let lhs = E::pairing(self.a, pk.w + pk.g2.mul(self.e));
        let rhs = E::pairing(b.into_affine(), pk.g2);

        lhs == rhs
    }

    pub fn verify_blind(&self, pk: &keygen::PublicKey<E>, commitment: &E::G1Affine) -> bool {
        let b = pk.g1 + pk.h0 * self.s + commitment;

        let lhs = E::pairing(self.a, pk.w + pk.g2.mul(self.e));
        let rhs = E::pairing(b.into_affine(), pk.g2);

        lhs == rhs
    }

    pub fn prepare_for_proof<R: Rng>(
        &self,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> RandomizedSignature<E> {
        RandomizedSignature::randomize(self, pk, messages, rng)
    }
}

impl<E: Pairing> RandomizedSignature<E> {
    pub(crate) fn randomize<R: Rng>(
        signature: &Signature<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Self {
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        let a_prime = signature.a.mul(r1).into_affine();

        let himi: E::G1 = E::G1::msm(&pk.h_l, messages).unwrap();
        let b = pk.g1 + pk.h0 * signature.s + himi;
        let a_bar = a_prime.mul(signature.e.neg()).add(b.mul(r1));

        let d = (b * r1) + (pk.h0 * r2.neg());

        let s_prime = signature.s - (r2 * r3);

        Self {
            a_prime,
            a_bar: a_bar.into_affine(),
            d: d.into_affine(),
            e: signature.e,
            s_prime,
            r1,
            r2,
            r3,
        }
    }

    pub fn verify_pairing(&self, pk: &keygen::PublicKey<E>) -> bool {
        let lhs = E::pairing(self.a_prime, pk.w);
        let rhs = E::pairing(self.a_bar, pk.g2);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let message_count = 4;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let signature = Signature::sign(pk, sk, &messages, &mut rng);
        let is_valid = signature.verify(pk, &messages);
        assert!(is_valid, "Signature verification failed");

        let randomized_signature = signature.prepare_for_proof(pk, &messages, &mut rng);
        assert!(
            randomized_signature.verify_pairing(pk),
            "Randomized signature verification failed"
        );
    }

    #[test]
    fn test_selective_disclosure_proof() {
        let mut rng = test_rng();
        let message_count = 5;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        // Create messages
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // Sign messages
        let signature = Signature::sign(pk, sk, &messages, &mut rng);

        // Verify the signature
        assert!(
            signature.verify(pk, &messages),
            "Signature verification failed"
        );

        // Create a selective disclosure proof
        let disclosed_indices = vec![0, 2]; // Disclose the first and third messages
        let proof_result = BBSPlusProofs::prove_selective_disclosure(
            &signature,
            pk,
            &messages,
            &disclosed_indices,
            &mut rng,
        );

        assert!(
            proof_result.is_ok(),
            "Failed to create selective disclosure proof"
        );

        let proof = proof_result.unwrap();

        // For now, let's just check that the proof is not empty
        assert!(!proof.is_empty(), "Proof should not be empty");

        // let deserialized_proof: SelectiveDisclosureProof<Bls12_381> =
        //     CanonicalDeserialize::deserialize_compressed(&proof[..]).unwrap();
        // assert_eq!(deserialized_proof.disclosed_messages.len(), disclosed_indices.len());
        // ... add more checks as needed
    }
}
