use crate::keygen::{PublicKey, SecretKey};
use crate::proofsystem::{BBSPlusProofOfKnowledge, CommitmentWithProof, ProofError, ProofSystem};
use crate::publicparams::PublicParams;
use crate::signature::{BBSPlusRandomizedSignature, BBSPlusSignature};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

/// Issuer's incomplete
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuerResponse<E: Pairing> {
    pub A: E::G1Affine,
    pub e: E::ScalarField,
    pub s_double_prime: E::ScalarField, // Issuer's blinding factor
}
pub struct AnonCredProtocol;
impl AnonCredProtocol {
    /// User creates a commitment to their messages and proves knowledge
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `messages` - Array of messages to commit to
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// * Commitment with proof and blinding factor
    pub fn obtain<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<(CommitmentWithProof<E>, E::ScalarField), ProofError> {
        // Generate random blinding factor s'
        let s_prime = E::ScalarField::rand(rng);

        // Create commitment and proof: cm = h_0^s' h_1^m_1 ... h_L^m_L
        let commitment_proof =
            ProofSystem::create_commitment_proof(pp, pk, messages, &s_prime, rng)?;

        Ok((commitment_proof, s_prime))
    }

    /// Issuer verifies the proof and issues a signature
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `sk` - Issuer's secret key
    /// * `pk` - Issuer's public key
    /// * `commitment_proof` - Commitment with proof from user
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// * Issuer's response containing signature components
    pub fn issue<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        sk: &SecretKey<E>,
        pk: &PublicKey<E>,
        commitment_proof: &CommitmentWithProof<E>,
        rng: &mut R,
    ) -> Result<IssuerResponse<E>, ProofError> {
        // Verify the proof of knowledge
        let is_valid = ProofSystem::verify_commitment_proof(pp, pk, commitment_proof)?;

        if !is_valid {
            return Err(ProofError::VerificationFailed);
        }

        // Generate random values for the signature
        let e = E::ScalarField::rand(rng);
        let s_double_prime = E::ScalarField::rand(rng);

        // Compute A = (g₁ · g₂^s'' · Cm)^(1/(e+x))
        let base = pp.g1 + pk.h0 * s_double_prime + commitment_proof.commitment;
        let exponent = (sk.x + e).inverse().ok_or(ProofError::VerificationFailed)?;
        let A = (base * exponent).into_affine();

        Ok(IssuerResponse {
            A,
            e,
            s_double_prime,
        })
    }

    /// User combines issuer response with their secrets to get a valid signature
    ///
    /// # Arguments
    /// * `s_prime` - User's blinding factor
    /// * `issuer_response` - Response from the issuer
    ///
    /// # Returns
    /// * Complete BBS+ signature
    pub fn complete_signature<E: Pairing>(
        s_prime: &E::ScalarField,
        issuer_response: &IssuerResponse<E>,
    ) -> BBSPlusSignature<E> {
        // Compute s = s' + s''
        let s = *s_prime + issuer_response.s_double_prime;

        // Construct the signature (A, e, s)
        BBSPlusSignature {
            A: issuer_response.A,
            e: issuer_response.e,
            s,
        }
    }

    /// User shows the credential by creating a randomized signature and proof
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `signature` - BBS+ signature
    /// * `messages` - Array of messages
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// * Randomized signature and proof
    pub fn show<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusSignature<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<(BBSPlusRandomizedSignature<E>, Vec<u8>), ProofError> {
        // Rerandomize the signature
        let randomized_signature = signature.rerandomize(pp, pk, messages, rng);

        // Generate the proof
        let proof = ProofSystem::bbs_plus_prove(pp, &randomized_signature, pk, messages, rng)?;

        // Return the randomized signature and the proof
        Ok((randomized_signature, proof))
    }

    /// Verifier checks the credential proof
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `serialized_proof` - Serialized proof from the user
    ///
    /// # Returns
    /// * Result indicating whether the proof is valid
    pub fn verify<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // Verify the proof
        let verification_result = ProofSystem::bbs_plus_verify_proof(pp, pk, serialized_proof)?;

        Ok(verification_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestSetup;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;

    #[test]
    fn test_obtain_issue_show_verify() {
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 4);

        // 1. Obtain: User creates commitment and proof
        let (commitment_proof, s_prime) =
            AnonCredProtocol::obtain(&setup.pp, &setup.pk, &setup.messages, &mut rng)
                .expect("Failed to create commitment");

        // 2. Issue: Issuer verifies and creates signature components
        let issuer_response =
            AnonCredProtocol::issue(&setup.pp, &setup.sk, &setup.pk, &commitment_proof, &mut rng)
                .expect("Failed to issue credential");

        // 3. Complete: User completes the signature
        let signature = AnonCredProtocol::complete_signature(&s_prime, &issuer_response);

        // 4. Show: User shows the credential
        let (randomized_signature, proof) =
            AnonCredProtocol::show(&setup.pp, &setup.pk, &signature, &setup.messages, &mut rng)
                .expect("Failed to generate proof");

        // 5. Verify: Verifier checks the credential
        let verification_result =
            AnonCredProtocol::verify(&setup.pp, &setup.pk, &proof).expect("Verification failed");

        assert!(verification_result, "Proof verification failed");
    }
}
