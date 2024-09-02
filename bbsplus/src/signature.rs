use crate::keygen;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use utils::helpers::Helpers;

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub a: E::G1Affine,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct RandomizedSignature<E: Pairing> {
    pub a_prime: E::G1Affine,
    pub a_bar: E::G1Affine,
    pub e: E::ScalarField,
    pub s_prime: E::ScalarField,
    pub r1: E::ScalarField,
    pub r2: E::ScalarField,
    pub r3: E::ScalarField,
    pub d: E::G1Affine,
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

    pub fn randomize<R: Rng>(
        &self,
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        rng: &mut R,
        messages: &Vec<E::ScalarField>,
    ) -> RandomizedSignature<E> {
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        let a_prime = self.a.mul(r1).into_affine();
        let a_bar = a_prime.mul(sk.x);

        let himi: E::G1 = E::G1::msm(&pk.h_l, messages).unwrap();
        let b = pk.g1 + pk.h0 * self.s + himi;

        let d = (b * r1) + (pk.h0 * r2.neg());

        let s_prime = self.s - (r2 * r3);

        RandomizedSignature {
            a_prime,
            a_bar: a_bar.into_affine(),
            e: self.e,
            s_prime,
            r1,
            r2,
            r3,
            d: d.into_affine(),
        }
    }
}

impl<E: Pairing> RandomizedSignature<E> {
    pub fn verify_pairing(&self, pk: &keygen::PublicKey<E>) -> bool {
        // let x = pk.w + pk.g2.mul(self.e); // X = w · g2^e = g2^(x+e)
        let lhs = E::pairing(self.a_prime, pk.w);
        let rhs = E::pairing(self.a_bar, pk.g2);

        lhs == rhs
    }

    // pub fn prove_spk() -> bool {}

    // pub fn verify_spk() -> bool {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{
        Bls12_381, Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine,
    };
    use ark_std::test_rng;
    use num::traits::ops::mul_add;
    use utils::helpers;

    #[test]
    fn test_sign_and_verify() {
        let mut rng = test_rng();
        let message_count = 4;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        // Create messages
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let signature = Signature::sign(pk, sk, &messages, &mut rng);
        let is_valid = signature.verify(pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Randomize signature
        let randomized_signature = signature.randomize(pk, sk, &mut rng, &messages);

        // Verify randomized signature
        assert!(
            randomized_signature.verify_pairing(pk),
            "Randomized signature verification failed"
        );
    }

    #[test]
    fn test_blind_sign() {
        let mut rng = test_rng();
        let message_count = 4;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        // Create messages
        let s1 = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // run proof of knowledge
        let mut bases = vec![pk.h0];
        bases.extend(pk.h_l.iter().cloned());

        // create fake challenge
        let challenge = Fr::rand(&mut rng);

        // generate commitment for proving
        let com_prime = SchnorrProtocol::commit(&bases, &mut rng);

        //         gather exponents to prove s1, m1, m2, ..., mi
        let mut exponents = vec![s1];
        exponents.extend(messages.iter().cloned());

        let public_commitment = G1Projective::msm_unchecked(&bases, &exponents).into_affine();

        let responses = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);

        let is_valid = SchnorrProtocol::verify(
            &bases,
            &public_commitment,
            &com_prime,
            &responses,
            &challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");

        let blind_signature = Signature::blind_sign(&pk, &sk, &public_commitment, &mut rng);

        let is_valid_signature = blind_signature.verify_blind(&pk, &public_commitment);
        assert!(is_valid_signature, "Signature verification failed");
    }

    #[test]
    fn test_sok() {
        let mut rng = test_rng();
        let message_count = 4;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        // Create messages
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let signature = Signature::sign(pk, sk, &messages, &mut rng);
        let is_valid = signature.verify(pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Randomize signature
        let randomized_signature = signature.randomize(pk, sk, &mut rng, &messages);

        // Verify randomized signature (A, e, s)
        assert!(
            randomized_signature.verify_pairing(pk),
            "Randomized signature verification failed"
        );

        // Verify abar/d = a'^-e . h_0^r2
        let lhs = randomized_signature.a_bar - randomized_signature.d;
        let rhs = randomized_signature
            .a_prime
            .mul(randomized_signature.e.neg())
            + pk.h0.mul(randomized_signature.r2);

        assert_eq!(
            lhs.into_affine(),
            rhs.into_affine(),
            "Manual verification failed: A'^-e · h0^r2 != Ābar/d"
        );

        // Set up the equation Ābar/d = A'^-e · h0^r2
        // Start SoK
        let bases = vec![randomized_signature.a_prime, pk.h0];
        let exponents = vec![randomized_signature.e.neg(), randomized_signature.r2];
        let abar = randomized_signature.a_bar;
        let d = randomized_signature.d;
        let public_commitment = (abar.add(d.neg())).into_affine();
        let challenge = Fr::rand(&mut rng);

        let schnorr_commitment_1 = SchnorrProtocol::commit(&bases, &mut rng);
        let schnorr_responses_1 =
            SchnorrProtocol::prove(&schnorr_commitment_1, &exponents, &challenge);
        let is_commitment1_valid = SchnorrProtocol::verify(
            &bases,
            &public_commitment,
            &schnorr_commitment_1,
            &schnorr_responses_1,
            &challenge,
        );
        assert!(is_commitment1_valid, "is commitment 1 valid, no!");

        // Set up the equation Ābar/d = A'^-e · h0^r2
        // Start SoK
        // Verify g1 * \prod_{i \in D}h_i^m_i      =     d^r3 * h_0^{-s'} * \prod_{i \notin D} hi^-mi
        let disclosed_indices: Vec<usize> = vec![0, 1];
        let mut disclosed_messages: Vec<<Bls12_381 as Pairing>::ScalarField> = vec![];
        let mut disclosed_bases: Vec<<Bls12_381 as Pairing>::G1Affine> = vec![];
        let mut hidden_messages: Vec<<Bls12_381 as Pairing>::ScalarField> = vec![];
        let mut hidden_bases: Vec<<Bls12_381 as Pairing>::G1Affine> = vec![];

        for (i, m) in messages.iter().enumerate() {
            if disclosed_indices.contains(&i) {
                println!("disclosed: {}, {}", &i, *m);
                disclosed_messages.push(*m);
                disclosed_bases.push(pk.h_l[i]);
            } else {
                println!("hidden: {}, {}", &i, *m);
                hidden_messages.push(*m);
                hidden_bases.push(pk.h_l[i].neg()); // we negate each hidden base to comply with the PoK operation
            }
        }

        let disclosed_lhs2: <Bls12_381 as Pairing>::G1 =
            <Bls12_381 as Pairing>::G1::msm(&disclosed_bases, &disclosed_messages).unwrap();
        let lhs2 = disclosed_lhs2.add(pk.g1);

        // d^r3 * h_0^{-s'} * \prod_{i \notin D} hi^-mi
        let dr3 = d.mul(randomized_signature.r3);
        let h0sprimeneg = pk.h0.mul(randomized_signature.s_prime.neg());
        let hidden_rhs2: <Bls12_381 as Pairing>::G1 =
            <Bls12_381 as Pairing>::G1::msm(&hidden_bases, &hidden_messages).unwrap();

        let rhs2 = dr3.add(h0sprimeneg).add(hidden_rhs2);
        assert_eq!(
            lhs2.into_affine(),
            rhs2.into_affine(),
            "Manual verification failed: g1 * prod_i in D h_i^m_i      =     d^r3 * h_0^-s' * prod_i notin D hi^-mi"
        );

        // Verify g1 * \prod_{i \in D}h_i^m_i      =     d^r3 * h_0^{-s'} * \prod_{i \notin D} hi^-mi
        // Start SoK
        // exponents = r3, -s, m_i \forall i \notin D
        // bases = d, h_0, h_i \forall i \notin D

        // Combine r3, -s, and hidden_messages into a single vector
        let mut exponents2: Vec<<Bls12_381 as Pairing>::ScalarField> =
            vec![randomized_signature.r3, randomized_signature.s_prime.neg()];
        exponents2.extend(hidden_messages);

        // Now you can use the exponents vector in your proof of knowledge
        let mut bases2 = vec![d, pk.h0];
        bases2.extend(hidden_bases);

        let public_commitment2 = lhs2;
        let challenge2 = Fr::rand(&mut rng);

        let schnorr_commitment_2 = SchnorrProtocol::commit(&bases2, &mut rng);
        let schnorr_responses_2 =
            SchnorrProtocol::prove(&schnorr_commitment_2, &exponents2, &challenge2);
        let is_commitment2_valid = SchnorrProtocol::verify(
            &bases2,
            &public_commitment2.into_affine(),
            &schnorr_commitment_2,
            &schnorr_responses_2,
            &challenge2,
        );

        assert!(is_commitment2_valid, "is commitment 2 valid, no!");
    }
}
