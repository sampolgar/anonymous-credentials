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
        &pp: &PublicParams<E>,
        &pk: &PublicKey<E>,
        rng: &mut impl Rng,
    ) -> RandomizedSignature {
    }
}

pub struct RandomizedSignature<E: Pairing> {
    A1: E::G1Affine,
    A1e: E::G1Affine,
    A2: E::G1Affine,
    pairing_statement: PairingOutput<E>,
    bases_g1: Vec<E::G1Affine>,
    bases_g2: Vec<E::G2Affine>,
    pairing_exponents: Vec<E::ScalarField>,
}

// impl<E: Pairing> ProofElements<E> {
//     pub fn new(
//         &pp: &PublicParams<E>,
//         &pk: &PublicKey<E>,
//         signature: &BBSPlusSignature<E>,
//         rng: &mut impl Rng,
//     ) -> Self {

//     }
//     // this is for the G1 elements of the verification. Basic for now, can improve later
//     /// Return vector of [A2, g2, g2, g1, g2,...,g_L] for e(g2,w)^r1 . e(g2,h0),...
//     ///
//     pub fn get_g2_g2_g1_g2_to_L(&self, A2: E::G1Affine) -> Vec<E::G1Affine> {
//         let mut bases: Vec<E::G1Affine> = Vec::new();
//         bases.push(A2);
//         bases.push(self.g2_to_L[0]);
//         bases.push(self.g2_to_L[0]);
//         bases.push(self.g1);
//         bases.extend(self.g2_to_L.iter().cloned());
//         bases
//     }
// }

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
