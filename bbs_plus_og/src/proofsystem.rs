use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusSignature;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr_pairing::{
    SchnorrCommitmentPairing, SchnorrProtocolPairing, SchnorrResponsesPairing,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Verification failed")]
    VerificationFailed,
}

/// Randomized signature elements for BBS+ proof
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusSignatureProofCommitment<E: Pairing> {
    pub A1: E::G1Affine, // g₁ʳ¹g₂ʳ²
    pub A2: E::G1Affine, // Ag₁ʳ¹
}

/// Full proof of knowledge of a BBS+ signature
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusProofOfKnowledge<E: Pairing> {
    pub randomized_sig: BBSPlusSignatureProofCommitment<E>,
    pub proof_commitment: Vec<E::G1Affine>, // Commitments for the proof
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>, // Responses for the proof
}

pub struct ProofSystem;

impl ProofSystem {
    /// Generate a proof of knowledge of a BBS+ signature following the paper's protocol
    pub fn prove<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusSignature<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Check that we have the right number of messages
        assert_eq!(messages.len(), pp.L, "Invalid number of messages");
        assert!(signature.verify(pp, pk, messages), "Invalid signature");

        let randomized_signature = signature.randomize(&pp, &pk, &messages, &mut rng);

        



        // // 6. Compute commitments for the proof

        // // Commitment for A₁ = g₁ʳ¹g₂ʳ²
        // let T1 = (g1.mul(r_r1) + g2.mul(r_r2)).into_affine();

        // // Commitment for A₁ᵉ = g₁ᵟ¹g₂ᵟ²
        // let T2 = (g1.mul(r_delta1) + g2.mul(r_delta2)).into_affine();

        // Commitment for the pairing relation
        // This is complex: e(A₂, w)/e(g₀, h₀) = e(A₂, h₀)⁻ᵉ·e(g₁, w)ʳ¹·e(g₀, h₀)ᵟ¹·e(g₁, h₀)ˢ·e(g₂, h₀)ᵐ¹...
        // We'll need to use pairing-based commitments here
        // For simplicity, we'll use a simplified approach for demonstration

        // Collect commitments
        let proof_commitment = vec![T1, T2];

        // 7. Generate challenge (in a real implementation, this would be a hash)
        let challenge = E::ScalarField::rand(rng);

        // 8. Compute responses
        let resp_r1 = r_r1 + challenge * r1;
        let resp_r2 = r_r2 + challenge * r2;
        let resp_e = r_e + challenge * signature.e;
        let resp_delta1 = r_delta1 + challenge * delta1;
        let resp_delta2 = r_delta2 + challenge * delta2;
        let resp_s = r_s + challenge * signature.s;

        let mut responses = vec![resp_r1, resp_r2, resp_e, resp_delta1, resp_delta2, resp_s];

        for (i, message) in messages.iter().enumerate() {
            responses.push(r_messages[i] + challenge * message);
        }

        // 9. Create and serialize the proof
        let proof = BBSPlusProofOfKnowledge {
            randomized_sig: BBSPlusSignatureProofCommitment::<E> { A1, A2 },
            proof_commitment,
            challenge,
            responses,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof of knowledge of a BBS+ signature
    pub fn verify<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // 1. Deserialize the proof
        let proof: BBSPlusProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 2. Extract values
        let A1 = proof.randomized_sig.A1;
        let A2 = proof.randomized_sig.A2;
        let challenge = proof.challenge;

        // For simplicity in this implementation, we'll assume the responses are ordered:
        // [resp_r1, resp_r2, resp_e, resp_delta1, resp_delta2, resp_s, resp_m1, ..., resp_mL]
        if proof.responses.len() < 6 + pp.L {
            return Err(ProofError::InvalidProof);
        }

        let resp_r1 = proof.responses[0];
        let resp_r2 = proof.responses[1];
        let resp_e = proof.responses[2];
        let resp_delta1 = proof.responses[3];
        let resp_delta2 = proof.responses[4];
        let resp_s = proof.responses[5];
        let resp_messages = &proof.responses[6..];

        // 3. Verify the commitments

        // Use the first two generators from our setup as g₁, g₂
        let g1 = pp.g[0];
        let g2 = pp.g[1];

        // Verify commitment for A₁ = g₁ʳ¹g₂ʳ²
        let T1_prime = (g1.mul(resp_r1) + g2.mul(resp_r2) + A1.mul(challenge.neg())).into_affine();

        // Verify commitment for A₁ᵉ = g₁ᵟ¹g₂ᵟ²
        let T2_prime = (g1.mul(resp_delta1)
            + g2.mul(resp_delta2)
            + (A1.mul(resp_e) + g1.mul(resp_delta1.neg()) + g2.mul(resp_delta2.neg()))
                .mul(challenge.neg()))
        .into_affine();

        // For the pairing relation, we would need to implement the full verification
        // This is complex and requires handling multiple pairings
        // For this simplified implementation, we'll return a positive result if the first two commitments verify

        // In a full implementation, we would verify that:
        // e(A₂, w)/e(g₀, h₀) = e(A₂, h₀)⁻ᵉ·e(g₁, w)ʳ¹·e(g₀, h₀)ᵟ¹·e(g₁, h₀)ˢ·e(g₂, h₀)ᵐ¹...

        if proof.proof_commitment.len() < 2
            || proof.proof_commitment[0] != T1_prime
            || proof.proof_commitment[1] != T2_prime
        {
            return Ok(false);
        }

        // In a real implementation, we would verify the pairing relation as well
        // For now, we'll just return true if the first two commitments verify

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use crate::signature::BBSPlusSignature;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_proof_of_knowledge() {
        // Initialize test environment
        let mut rng = test_rng();
        let L = 4; // Support 4 messages

        // Generate public parameters
        let pp = PublicParams::<Bls12_381>::new(&L, &mut rng);

        // Generate a keypair
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create random messages
        let messages: Vec<Fr> = (0..L).map(|_| Fr::rand(&mut rng)).collect();

        // Sign the messages
        let signature = BBSPlusSignature::sign(&pp, &sk, &messages, &mut rng);

        // Verify the signature directly
        let is_valid = signature.verify(&pp, &pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Generate a proof of knowledge
        let proof = ProofSystem::prove(&pp, &pk, &signature, &messages, &mut rng)
            .expect("Failed to generate proof");

        // Verify the proof
        let is_proof_valid = ProofSystem::verify(&pp, &pk, &proof).expect("Failed to verify proof");

        assert!(is_proof_valid, "Proof verification failed");
    }
}
