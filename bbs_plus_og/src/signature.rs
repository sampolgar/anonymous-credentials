use crate::keygen::{PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use crate::utils::BBSPlusOgUtils;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::ops::{Add, Mul};
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use ark_std::One;
use std::ops::Neg;

#[derive(Clone, Debug)]
pub struct BBSPlusSignature<E: Pairing> {
    pub A: E::G1Affine,
    pub e: E::ScalarField,
    pub s: E::ScalarField,
}

impl<E: Pairing> BBSPlusSignature<E> {
    /// Generate a BBS+ signature on a message vector
    /// As per the paper: "Signing block of messages. On input (m₁,...,mₗ) ∈ ℤᵖᴸ,
    /// choose e and a random number s, compute A = [g₀g₁ᵐ¹g₂ᵐ²...g_{L+1}ˢ]^(1/(e+γ)).
    /// Signature on (m₁,...,mₗ) is (A,e,s)."
    pub fn sign(
        pp: &PublicParams<E>,
        sk: &SecretKey<E>,
        messages: &[E::ScalarField],
        rng: &mut impl Rng,
    ) -> Self {
        assert!(messages.len() <= pp.L, "Too many messages");

        // Choose random e, s
        let e = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        let bases = pp.get_all_bases();
        let mut exponents =
            BBSPlusOgUtils::add_scalar_to_start_of_vector::<E>(&messages, &E::ScalarField::one());
        // Compute A = (g₀·Π(g_i^m_i)·g_{L+1}^s)^(1/(e+γ))
        exponents.push(s);

        // Compute base = g₀·Π(g_i^m_i)·g_{L+1}^s
        let base = E::G1::msm_unchecked(&bases, &exponents).into_affine();

        // Compute exponent = 1/(e+γ)
        let exponent = (e + sk.gamma).inverse().expect("e+γ should be invertible");

        // Compute A = base^exponent
        let A = base.mul(exponent).into_affine();

        Self { A, e, s }
    }

    /// Verify a BBS+ signature on a message vector
    /// As per the paper: "Signature Verification. To verify a signature (A,e,s) on
    /// (m₁,...,mₗ), check if e(A,wh₀ᵉ) = e(g₀g₁ᵐ¹g₂ᵐ²...g_{L+1}ˢ,h₀)."
    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
    ) -> bool {
        assert!(messages.len() <= pp.L, "Too many messages");

        let bases = pp.get_all_bases();
        let mut exponents =
            BBSPlusOgUtils::add_scalar_to_start_of_vector::<E>(&messages, &E::ScalarField::one());
        // Compute A = (g₀·Π(g_i^m_i)·g_{L+1}^s)^(1/(e+γ))
        exponents.push(self.s);

        // Compute base = g₀·Π(g_i^m_i)·g_{L+1}^s
        let base = E::G1::msm_unchecked(&bases, &exponents).into_affine();

        // Verify e(A, w·h₀ᵉ) = e(base, h₀)
        let lhs = E::pairing(self.A, (pk.w + pp.h0.mul(self.e)).into_affine());

        let rhs = E::pairing(base, pp.h0);

        lhs == rhs
    }

    pub fn randomize(
        &self,
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut impl Rng,
    ) -> RandomizedSignature<E> {
        RandomizedSignature::new(pp, pk, self, messages, rng)
    }
}

pub struct RandomizedSignature<E: Pairing> {
    pub r1: E::ScalarField,
    pub r2: E::ScalarField,
    pub delta1: E::ScalarField,
    pub delta2: E::ScalarField,
    pub A1: E::G1Affine,  //g1^r1 g2^r2
    pub A1e: E::G1Affine, // g1^delta1 g2^delta2
    pub A2: E::G1Affine,  // A . g_2^r1
    pub pairing_statement: PairingOutput<E>,
    pub pairing_bases_g1: Vec<E::G1Affine>,
    pub pairing_bases_g2: Vec<E::G2Affine>,
    pub pairing_exponents: Vec<E::ScalarField>,
}

impl<E: Pairing> RandomizedSignature<E> {
    pub fn new(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusSignature<E>,
        messages: &[E::ScalarField],
        rng: &mut impl Rng,
    ) -> Self {
        // Compute A1 = g1r1 g2r2
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let (g1, g2) = pp.get_g1_g2();
        let A1 = g1.mul(r1) + g2.mul(r2);

        // Compute A2 = A . g_2^r1
        let A2 = signature.A.into_group() + g2.mul(r1);

        let delta1 = r1 * signature.e;
        let delta2 = r2 * signature.e;

        let A1e = A1 * signature.e;

        assert_eq!(
            A1e,
            g1 * delta1 + g2 * delta2,
            "a1e and g1delta1 g2delta2 aren't equal"
        );

        // one of the rhs is neg
        let pairing_statement = BBSPlusOgUtils::compute_gt(
            &[A2.into_affine(), pp.g0.into_group().neg().into_affine()],
            &[pk.w, pp.h0],
        );

        // e(A2,h0) . e(g2,w) . e(g2, h0) . e(g1, h0) . e(g2, h0), ..e(g_L, h0)
        let mut pairing_bases_g1: Vec<E::G1Affine> = Vec::new();
        pairing_bases_g1.push(A2.into_affine());    
        pairing_bases_g1.push(pp.g2_to_L[0]);
        pairing_bases_g1.push(pp.g2_to_L[0]);
        pairing_bases_g1.push(pp.g1);
        pairing_bases_g1.extend(pp.g2_to_L.iter().cloned());

        let mut pairing_bases_g2 =
            BBSPlusOgUtils::copy_point_to_length_g2::<E>(pp.h0, &pairing_bases_g1.len());
        pairing_bases_g2[1] = pk.w;

        // [-e, r1, delta1, s, m1,...,mL]
        let mut pairing_exponents: Vec<E::ScalarField> = Vec::new();
        pairing_exponents.push(-signature.e);
        pairing_exponents.push(r1);
        pairing_exponents.push(delta1);
        pairing_exponents.push(signature.s);
        pairing_exponents.extend(messages.iter().cloned());

        Self {
            r1,
            r2,
            delta1,
            delta2,
            A1: A1.into_affine(),
            A1e: A1e.into_affine(),
            A2: A2.into_affine(),
            pairing_statement,
            pairing_bases_g1,
            pairing_bases_g2,
            pairing_exponents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_signature() {
        // Initialize test environment
        let mut rng = ark_std::test_rng();
        let L = 5; // Support 5 messages

        // Generate public parameters
        let pp = PublicParams::<Bls12_381>::new(&L, &mut rng);

        // Generate a keypair
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create random messages
        let messages: Vec<Fr> = (0..L).map(|_| Fr::rand(&mut rng)).collect();

        // Sign the messages
        let signature = BBSPlusSignature::sign(&pp, &sk, &messages, &mut rng);

        // Verify the signature
        let is_valid = signature.verify(&pp, &pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Test with modified messages
        let mut modified_messages = messages.clone();
        modified_messages[1] = Fr::rand(&mut rng);
        let is_invalid = signature.verify(&pp, &pk, &modified_messages);
        assert!(
            !is_invalid,
            "Signature should not verify with modified messages"
        );
    }
}
