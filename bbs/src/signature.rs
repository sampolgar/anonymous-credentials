use crate::keygen;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    One, Zero,
};
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
}

impl<E: Pairing> Signature<E> {
    pub fn sign<R: Rng>(
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Self {
        assert_eq!(messages.len(), pk.h.len(), "Invalid number of messages");

        let e = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        let mut b = pk.h0.into_group();
        for (h_i, m_i) in pk.h.iter().zip(messages.iter()) {
            b += h_i.mul(*m_i);
        }

        let exp = sk.x + e;
        let a = (b + pk.h0.mul(s)).mul(exp.inverse().unwrap()).into_affine();

        Self { a, e, s }
    }

    pub fn verify(&self, pk: &keygen::PublicKey<E>, messages: &[E::ScalarField]) -> bool {
        assert_eq!(messages.len(), pk.h.len(), "Invalid number of messages");

        let mut b = pk.h0.into_group();
        for (h_i, m_i) in pk.h.iter().zip(messages.iter()) {
            b += h_i.mul(*m_i);
        }
        b += pk.h0.mul(self.s);

        let lhs = E::pairing(self.a, pk.w + pk.g2.mul(self.e));
        let rhs = E::pairing(b.into_affine(), pk.g2);

        lhs == rhs
    }

    pub fn randomize<R: Rng>(
        &self,
        pk: &keygen::PublicKey<E>,
        rng: &mut R,
    ) -> RandomizedSignature<E> {
        let r1 = loop {
            let r = E::ScalarField::rand(rng);
            if !r.is_zero() {
                break r;
            }
        };
        let r2 = E::ScalarField::rand(rng);
        let r3 = r1.inverse().unwrap();

        let a_prime = self.a.mul(r1).into_affine();
        let a_bar = a_prime.mul(self.e.neg()) + pk.h0.mul(r2);
        let s_prime = self.s + (r2 * r3);

        RandomizedSignature {
            a_prime,
            a_bar: a_bar.into_affine(),
            e: self.e,
            s_prime,
        }
    }

    // pub fn generate_proof<R: Rng>(
    //     &self,
    //     pk: &keygen::PublicKey<E>,
    //     messages: &[E::ScalarField],
    //     revealed_indices: &[usize],
    //     rng: &mut R,
    // ) -> BBSProof<E> {
    //     // Implement proof generation logic here
    //     // This is a complex process involving commitment schemes and zero-knowledge proofs
    //     // The actual implementation depends on the specific BBS+ variant and proof system used
    //     unimplemented!("Proof generation not implemented yet")
    // }
}

impl<E: Pairing> RandomizedSignature<E> {
    pub fn verify(&self, pk: &keygen::PublicKey<E>) -> bool {
        let x = pk.w + pk.g2.mul(self.e); // X = w · g2^e = g2^(x+e)
        let lhs = E::pairing(self.a_prime, x);
        let rhs = E::pairing(self.a_bar, pk.g2);

        lhs == rhs
    }
}

// pub struct BBSProof<E: Pairing> {
//     // Define proof components here
//     // This structure will depend on the specific proof system used with BBS+
// }

// impl<E: Pairing> BBSProof<E> {
//     pub fn verify(
//         &self,
//         pk: &keygen::PublicKey<E>,
//         revealed_messages: &[(usize, E::ScalarField)],
//     ) -> bool {
//         // Implement proof verification logic here
//         unimplemented!("Proof verification not implemented yet")
//     }
// }

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

        // Create messages
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let signature = Signature::sign(pk, sk, &messages, &mut rng);
        let is_valid = signature.verify(pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Randomize signature
        let randomized_signature = signature.randomize(pk, &mut rng);

        // Verify randomized signature
        assert!(
            randomized_signature.verify(pk),
            "Randomized signature verification failed"
        );
    }
}
