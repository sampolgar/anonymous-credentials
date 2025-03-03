use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusSignature;
use crate::utils::BBSPlusOgUtils;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
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
        // rng: &mut impl Rng,
    ) -> Result<Vec<u8>, ProofError> {
        // Check that we have the right number of messages
        assert_eq!(messages.len(), pp.L, "Invalid number of messages");
        assert!(signature.verify(pp, pk, messages), "Invalid signature");
        let challenge = E::ScalarField::rand(rng);

        let rand_sig = signature.randomize(&pp, &pk, &messages, rng);

        // Schnorr for Statement / Proof 1
        // PoK A1 = g1^r1 g2^r2
        // schnorr_commitment1 = g1^rho_r1 * g2^rho_r2
        let rho_r1 = E::ScalarField::rand(rng);
        let rho_r2 = E::ScalarField::rand(rng);
        let statement1 = rand_sig.A1;
        let (g1, g2) = pp.get_g1_g2();
        let bases1: Vec<<E as Pairing>::G1Affine> = vec![g1, g2];
        let exponents1 = vec![rand_sig.r1, rand_sig.r2];
        let blinding_factors1 = vec![rho_r1, rho_r2];
        let schnorr_commitment1 =
            SchnorrProtocol::commit_with_prepred_blindness(&bases1, &blinding_factors1);
        let schnorr_responses1 =
            SchnorrProtocol::prove(&schnorr_commitment1, &exponents1, &challenge);

        assert!(
            SchnorrProtocol::verify(
                &bases1,
                &statement1,
                &schnorr_commitment1,
                &schnorr_responses1,
                &challenge
            ),
            "schnorr 1 isn't valid"
        );
        println!("schnorr 1 is valid");

        // // schnorr commitment2 = g1^rho3, g2^rho4
        let rho_delta1 = E::ScalarField::rand(rng);
        let rho_delta2 = E::ScalarField::rand(rng);
        let blinding_factors2 = vec![rho_delta1, rho_delta2];
        let statement2 = rand_sig.A1.mul(signature.e).into_affine();
        let bases2 = bases1;
        let exponents2 = vec![rand_sig.delta1, rand_sig.delta2];
        let schnorr_commitment2 =
            SchnorrProtocol::commit_with_prepred_blindness(&bases2, &blinding_factors2);
        let schnorr_responses2 =
            SchnorrProtocol::prove(&schnorr_commitment2, &exponents2, &challenge);
        assert!(
            SchnorrProtocol::verify(
                &bases2,
                &statement2,
                &schnorr_commitment2,
                &schnorr_responses2,
                &challenge
            ),
            "schnorr 2 isn't valid"
        );
        println!("schnorr 2 is valid");

        // PoK
        let rho_neg_e = E::ScalarField::rand(rng);
        let rho_s = E::ScalarField::rand(rng);
        let rho_messages: Vec<E::ScalarField> = (0..messages.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        let statement3 = rand_sig.pairing_statement;
        let exponents3 = rand_sig.pairing_exponents;

        // [rho_neg_e, rho_r1, rho_delta1, rho_s, rho_m1,...,mL]
        let blinding_factors3_temp = vec![rho_neg_e, rho_r1, rho_delta1, rho_s];
        let blindind_factors3 =
            BBSPlusOgUtils::concatenate_scalars::<E>(&blinding_factors3_temp, &rho_messages);

        assert_eq!(
            blinding_factors3_temp[0], blindind_factors3[0],
            "zeros of blinding factors aren't equal"
        );

        assert_eq!(
            blindind_factors3.len(),
            rand_sig.pairing_bases_g1.len(),
            "public_generators lengths must match"
        );

        let schnorr_commitment3 = SchnorrProtocolPairing::commit_with_prepared_blindness::<E>(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &blindind_factors3,
        );

        let schnorr_commitment_gt = schnorr_commitment3.schnorr_commitment;

        let schnorr_responses3 =
            SchnorrProtocolPairing::prove(&schnorr_commitment3, &exponents3, &challenge);

        assert!(
            SchnorrProtocolPairing::verify(
                &statement3,
                &schnorr_commitment_gt,
                &challenge,
                &rand_sig.pairing_bases_g1,
                &rand_sig.pairing_bases_g2,
                &schnorr_responses3.0,
            ),
            "pairing protocol not verified"
        );

        let mut serialized_proof = Vec::new();
        // proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    // /// Verify a proof of knowledge of a BBS+ signature
    // pub fn verify<E: Pairing>(
    //     pp: &PublicParams<E>,
    //     pk: &PublicKey<E>,
    //     serialized_proof: &[u8],
    // ) -> Result<bool, ProofError> {
    //     // 1. Deserialize the proof
    //     let proof: BBSPlusProofOfKnowledge<E> =
    //         CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

    //     // 2. Extract values
    //     let A1 = proof.randomized_sig.A1;
    //     let A2 = proof.randomized_sig.A2;
    //     let challenge = proof.challenge;

    //     // For simplicity in this implementation, we'll assume the responses are ordered:
    //     // [resp_r1, resp_r2, resp_e, resp_delta1, resp_delta2, resp_s, resp_m1, ..., resp_mL]
    //     if proof.responses.len() < 6 + pp.L {
    //         return Err(ProofError::InvalidProof);
    //     }

    //     let resp_r1 = proof.responses[0];
    //     let resp_r2 = proof.responses[1];
    //     let resp_e = proof.responses[2];
    //     let resp_delta1 = proof.responses[3];
    //     let resp_delta2 = proof.responses[4];
    //     let resp_s = proof.responses[5];
    //     let resp_messages = &proof.responses[6..];

    //     // 3. Verify the commitments

    //     // Use the first two generators from our setup as g₁, g₂
    //     let g1 = pp.g[0];
    //     let g2 = pp.g[1];

    //     // Verify commitment for A₁ = g₁ʳ¹g₂ʳ²
    //     let T1_prime = (g1.mul(resp_r1) + g2.mul(resp_r2) + A1.mul(challenge.neg())).into_affine();

    //     // Verify commitment for A₁ᵉ = g₁ᵟ¹g₂ᵟ²
    //     let T2_prime = (g1.mul(resp_delta1)
    //         + g2.mul(resp_delta2)
    //         + (A1.mul(resp_e) + g1.mul(resp_delta1.neg()) + g2.mul(resp_delta2.neg()))
    //             .mul(challenge.neg()))
    //     .into_affine();

    //     // For the pairing relation, we would need to implement the full verification
    //     // This is complex and requires handling multiple pairings
    //     // For this simplified implementation, we'll return a positive result if the first two commitments verify

    //     // In a full implementation, we would verify that:
    //     // e(A₂, w)/e(g₀, h₀) = e(A₂, h₀)⁻ᵉ·e(g₁, w)ʳ¹·e(g₀, h₀)ᵟ¹·e(g₁, h₀)ˢ·e(g₂, h₀)ᵐ¹...

    //     if proof.proof_commitment.len() < 2
    //         || proof.proof_commitment[0] != T1_prime
    //         || proof.proof_commitment[1] != T2_prime
    //     {
    //         return Ok(false);
    //     }

    //     // In a real implementation, we would verify the pairing relation as well
    //     // For now, we'll just return true if the first two commitments verify

    //     Ok(true)
    // }
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

        // // Verify the proof
        // let is_proof_valid = ProofSystem::verify(&pp, &pk, &proof).expect("Failed to verify proof");

        // assert!(is_proof_valid, "Proof verification failed");
    }
}
