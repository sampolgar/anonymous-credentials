use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusSignature;
use crate::utils::BBSPlusOgUtils;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
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
        // let exponents3 = rand_sig.pairing_exponents;

        // [rho_neg_e, rho_r1, rho_delta1, rho_s, rho_m1,...,mL]
        let blinding_factors3_temp = vec![rho_neg_e, rho_r1, rho_delta1, rho_s];
        let blinding_factors3 =
            BBSPlusOgUtils::concatenate_scalars::<E>(&blinding_factors3_temp, &rho_messages);

        assert_eq!(
            blinding_factors3_temp[0], blinding_factors3[0],
            "zeros of blinding factors aren't equal"
        );

        assert_eq!(
            blinding_factors3.len(),
            rand_sig.pairing_bases_g1.len(),
            "public_generators lengths must match"
        );
        let gt1 = vec![rand_sig.A2, pp.g0];
        let gt2 = vec![pk.w, pp.h0];
        let scalaers = vec![E::ScalarField::one(), -E::ScalarField::one()];
        let gt = BBSPlusOgUtils::compute_gt_from_g1_g2_scalars::<E>(&gt1, &gt2, &scalaers);
        assert_eq!(
            gt, rand_sig.pairing_statement,
            "pairing statement not equal"
        );
        println!("pairinng statemnet equal");

        // Start with empty vectors
        let mut pairing_bases_g11: Vec<E::G1Affine> = Vec::new();
        let mut pairing_bases_g22: Vec<E::G2Affine> = Vec::new();
        let mut pairing_exponents2: Vec<E::ScalarField> = Vec::new();

        // Add e(A₂,h₀)⁻ᵉ term
        pairing_bases_g11.push(rand_sig.A2);
        pairing_bases_g22.push(pp.h0);
        pairing_exponents2.push(-signature.e); // This should be negative

        // Add e(g₂,w)ʳ¹ term
        pairing_bases_g11.push(pp.g2_to_L[0]); // g₂
        pairing_bases_g22.push(pk.w);
        pairing_exponents2.push(rand_sig.r1); // POSITIVE

        // Add e(g₂,h₀)ᵟ¹ term
        pairing_bases_g11.push(pp.g2_to_L[0]); // g₂
        pairing_bases_g22.push(pp.h0);
        pairing_exponents2.push(rand_sig.delta1); // POSITIVE

        // Add e(g₁,h₀)ˢ term
        pairing_bases_g11.push(pp.g1);
        pairing_bases_g22.push(pp.h0);
        pairing_exponents2.push(signature.s); // POSITIVE

        // Add e(g₂,h₀)ᵐ¹...e(gL+1,h₀)ᵐᴸ terms
        for i in 0..messages.len() {
            pairing_bases_g11.push(pp.g2_to_L[i]); // For message terms
            pairing_bases_g22.push(pp.h0);
            pairing_exponents2.push(messages[i]); // POSITIVE
        }

        // for i in 0..pairing_bases_g11.len() {
        //     println!(
        //         "i at: {}, base1{}, base2, {}",
        //         i, pairing_bases_g11[i], rand_sig.pairing_bases_g1[i]
        //     );
        //     assert_eq!(
        //         pairing_bases_g11[i], rand_sig.pairing_bases_g1[i],
        //         "base g1 wasn't equal"
        //     );
        //     assert_eq!(
        //         pairing_bases_g22[i], rand_sig.pairing_bases_g2[i],
        //         "base g2 wasn't equal"
        //     );
        //     assert_eq!(
        //         pairing_exponents2[i], rand_sig.pairing_exponents[i],
        //         "exponents wasn't equal"
        //     );
        // }

        let schnorr_commitment3 = SchnorrProtocolPairing::commit_with_prepared_blindness::<E>(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &blinding_factors3,
        );

        let schnorr_commitment_gt = schnorr_commitment3.schnorr_commitment;

        let schnorr_responses3 = SchnorrProtocolPairing::prove(
            &schnorr_commitment3,
            &rand_sig.pairing_exponents,
            &challenge,
        );

        println!("Blinding factors vs exponents:");
        for i in 0..3 {
            println!(
                "Index {}: Blinding={}, Exponent={}",
                i, blinding_factors3[i], rand_sig.pairing_exponents[i]
            );
        }

        println!(
            "Commitment bases lengths: g1={}, g2={}, blindings={}",
            rand_sig.pairing_bases_g1.len(),
            rand_sig.pairing_bases_g2.len(),
            blinding_factors3.len()
        );

        // Check a sample of the responses
        println!(
            "Response samples: [{}, {}, {}]",
            schnorr_responses3.0[0], schnorr_responses3.0[1], schnorr_responses3.0[2]
        );
        println!(
            "Expected: [{}, {}, {}]",
            blinding_factors3[0] + (rand_sig.pairing_exponents[0] * challenge),
            blinding_factors3[1] + (rand_sig.pairing_exponents[1] * challenge),
            blinding_factors3[2] + (rand_sig.pairing_exponents[2] * challenge)
        );

        // responses need to be equal at some positions
        // responses [1] = r1
        // responses [2] = delta1
        assert_eq!(
            schnorr_responses3.0[1], schnorr_responses1.0[0],
            "responses for r1 aren't equal"
        );
        assert_eq!(
            schnorr_responses3.0[2], schnorr_responses2.0[0],
            "responses for rho1 aren't equal"
        );

        // Compute left-hand side directly
        let lhs = BBSPlusOgUtils::compute_gt_from_g1_g2_scalars(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &schnorr_responses3.0,
        );

        // Compute right-hand side components
        let rhs1 = statement3.mul_bigint(challenge.into_bigint());
        let rhs2 = schnorr_commitment_gt;
        let rhs = rhs1 + rhs2;

        println!("Verification values:");
        println!("LHS == RHS: {}", lhs == rhs);
        println!(
            "Base lengths match: {}",
            rand_sig.pairing_bases_g1.len() == rand_sig.pairing_bases_g2.len()
                && rand_sig.pairing_bases_g1.len() == schnorr_responses3.0.len()
        );

        let lhs = BBSPlusOgUtils::compute_gt_from_g1_g2_scalars::<E>(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &schnorr_responses3.0,
        );

        let statement_part = statement3.mul_bigint(challenge.into_bigint());
        let rhs = statement_part + schnorr_commitment_gt;

        // Print hex representation to see exact values
        // println!("LHS bytes: {:?}", lhs.to_bytes());
        // println!("RHS bytes: {:?}", rhs.to_bytes());

        // Try a direct verification approach
        // Instead of using the SchnorrProtocolPairing::verify function,
        // manually compute each side

        // 1. First, calculate each pairing individually for the LHS
        let mut lhs_product = E::TargetField::one();
        for i in 0..rand_sig.pairing_bases_g1.len() {
            // Compute e(g1[i]^response[i], g2[i])
            let g1_scaled = rand_sig.pairing_bases_g1[i]
                .mul(schnorr_responses3.0[i])
                .into_affine();
            let single_pairing = E::pairing(g1_scaled, rand_sig.pairing_bases_g2[i]);
            lhs_product = lhs_product + single_pairing.0;
        }

        // 2. For the RHS, calculate statement^challenge * commitment separately
        let statement_raised = statement3.mul_bigint(&challenge.into_bigint());
        let rhs_product = statement_raised + schnorr_commitment_gt;

        println!("Manual verification: {}", lhs_product == rhs_product.0);

        // Try a completely different approach by computing all the pairings
        // in the original equation format

        // 1. Compute LHS: e(A₂,w)/e(g₀,h₀)
        let left_numerator = E::pairing(rand_sig.A2, pk.w);
        let left_denominator = E::pairing(pp.g0, pp.h0);
        let left_side = left_numerator.0 + left_denominator.0.inverse().unwrap();

        // 2. Compute RHS: e(A₂,h₀)⁻ᵉ·e(g₂,w)ʳ¹·e(g₂,h₀)ᵟ¹·e(g₁,h₀)ˢ·...
        let mut right_side = E::TargetField::one();

        // e(A₂,h₀)⁻ᵉ
        let term1 = E::pairing(rand_sig.A2, pp.h0).mul_bigint(&(-signature.e).into_bigint());
        right_side = right_side + term1.0;

        // e(g₂,w)ʳ¹
        let term2 = E::pairing(pp.g2_to_L[0], pk.w).mul_bigint(&rand_sig.r1.into_bigint());
        right_side = right_side + term2.0;

        // e(g₂,h₀)ᵟ¹
        let term3 = E::pairing(pp.g2_to_L[0], pp.h0).mul_bigint(&rand_sig.delta1.into_bigint());
        right_side = right_side + term3.0;

        // e(g₁,h₀)ˢ
        let term4 = E::pairing(pp.g1, pp.h0).mul_bigint(&signature.s.into_bigint());
        right_side = right_side + term4.0;

        // Message terms
        for i in 0..messages.len() {
            let term = E::pairing(pp.g2_to_L[i], pp.h0).mul_bigint(&messages[i].into_bigint());
            right_side = right_side + term.0;
        }

        println!("Original equation check: {}", left_side == right_side);

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
        let L = 1; // Support 4 messages

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
