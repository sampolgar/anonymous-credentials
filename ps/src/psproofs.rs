use crate::{keygen, signature::Signature, test_helpers::PSTestSetup};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use rayon::prelude::*;
use schnorr::schnorr_pairing::{SchnorrCommitmentPairing, SchnorrProtocolPairing};
use thiserror::Error;
use utils::helpers::Helpers;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofOfKnowledge<E: Pairing> {
    pub randomized_signature: (E::G1Affine, E::G1Affine),
    pub signature_commitment: PairingOutput<E>,
    pub schnorr_commitment: PairingOutput<E>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SelectiveDisclosureProof<E: Pairing> {
    pub randomized_signature: (E::G1Affine, E::G1Affine),
    pub signature_commitment: PairingOutput<E>,
    pub witness_commitment: PairingOutput<E>,
    pub schnorr_commitment: PairingOutput<E>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
    pub disclosed_messages: Vec<(usize, E::ScalarField)>,
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid disclosed index")]
    InvalidDisclosedIndex,
    #[error("Too many disclosed indices")]
    TooManyDisclosedIndices,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    // Add other error types as needed
}

pub struct PSProofs;

impl PSProofs {
    pub fn prove_knowledge<E: Pairing>(setup: &PSTestSetup<E>) -> Vec<u8> {
        let mut rng = ark_std::test_rng();
        let r = E::ScalarField::rand(&mut rng);
        let tt = E::ScalarField::rand(&mut rng);
        let sigma_prime = setup.signature.randomize_for_pok(&r, &tt);

        // Generate a commitment to the signature
        let signature_commitment_gt = sigma_prime.generate_commitment_gt(&setup.pk);

        // Generate commitment to secret exponents tt, m1, ... ,mn
        let base_length = setup.messages.len() + 1;
        let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &base_length);
        let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

        let schnorr_commitment_gt =
            SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);

        let challenge = E::ScalarField::rand(&mut rng);

        // generate message vector
        let m_vector = Helpers::add_scalar_to_vector::<E>(&tt, &setup.messages);
        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &m_vector, &challenge);

        let proof = ProofOfKnowledge {
            randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
            signature_commitment: signature_commitment_gt,
            schnorr_commitment: schnorr_commitment_gt.t_com,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof).unwrap();
        // proof.serialize(&mut serialized_proof).unwrap();
        serialized_proof
    }

    pub fn verify_knowledge<E: Pairing>(setup: &PSTestSetup<E>, serialized_proof: &[u8]) -> bool {
        let proof: ProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof).unwrap();

        let computed_signature_commitment = Helpers::compute_gt::<E>(
            &[
                proof.randomized_signature.1,
                proof
                    .randomized_signature
                    .0
                    .into_group()
                    .neg()
                    .into_affine(),
            ],
            &[setup.pk.g2, setup.pk.x_g2],
        );

        assert_eq!(
            computed_signature_commitment, proof.signature_commitment,
            "must be equal"
        );

        // 2. Prepare bases for verification
        let base_length = setup.messages.len() + 1;
        let bases_g1 =
            Helpers::copy_point_to_length_g1::<E>(proof.randomized_signature.0, &base_length);
        let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

        // 3. Verify the Schnorr proof
        let is_valid = SchnorrProtocolPairing::verify(
            &proof.schnorr_commitment,
            &proof.signature_commitment,
            &proof.challenge,
            &bases_g1,
            &bases_g2,
            &proof.responses,
        );

        assert_eq!(
            proof.responses.len(),
            base_length,
            "responses and base length don't match"
        );

        is_valid
    }

    pub fn prove_selective_disclosure<E: Pairing, R: Rng>(
        setup: &PSTestSetup<E>,
        disclosed_indices: &[usize],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        let message_count = setup.messages.len() - 1; //-1 for t?
        if disclosed_indices.iter().any(|&i| i >= setup.messages.len()) {
            return Err(ProofError::InvalidDisclosedIndex);
        }
        if disclosed_indices.len() > setup.messages.len() {
            return Err(ProofError::TooManyDisclosedIndices);
        }
        // Randomize signature
        let t = E::ScalarField::rand(rng);
        let sigma_prime = setup.signature.randomize_for_pok_new(rng, &t);
        // Generate signature commitment
        let signature_commitment = Helpers::compute_gt::<E>(
            &[
                sigma_prime.sigma2,
                sigma_prime.sigma1.into_group().neg().into_affine(),
            ],
            &[setup.pk.g2, setup.pk.x_g2],
        );

        // Split messages into disclosed and hidden
        let mut disclosed_messages = vec![];
        let mut hidden_messages = vec![];
        let mut hidden_bases_g2 = vec![];

        for (i, m) in setup.messages.iter().enumerate() {
            if i < message_count {
                if disclosed_indices.contains(&i) {
                    disclosed_messages.push((i, *m));
                } else {
                    hidden_messages.push(*m);
                    hidden_bases_g2.push(setup.pk.y_g2[i]);
                }
            } else {
                // This is tt (the last element)
                hidden_messages.push(*m);
                hidden_bases_g2.push(setup.pk.g2);
            }
        }

        // Commit to hidden messages
        let bases_g1 =
            Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &hidden_bases_g2.len());
        let witness_commitment = Helpers::compute_gt_from_g1_g2_scalars::<E>(
            &bases_g1,
            &hidden_bases_g2,
            &hidden_messages,
        );

        // Generate Schnorr commitment
        let schnorr_commitment =
            SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &hidden_bases_g2, rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(rng);

        // Generate responses
        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment, &hidden_messages, &challenge);

        // Create and serialize the proof
        let proof = SelectiveDisclosureProof::<E> {
            randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
            signature_commitment,
            witness_commitment,
            schnorr_commitment: schnorr_commitment.t_com,
            challenge,
            responses: responses.0,
            disclosed_messages,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn verify_selective_disclosure<E: Pairing>(
        setup: &PSTestSetup<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        let proof: SelectiveDisclosureProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify signature commitment
        let computed_signature_commitment = Helpers::compute_gt::<E>(
            &[
                proof.randomized_signature.1,
                proof
                    .randomized_signature
                    .0
                    .into_group()
                    .neg()
                    .into_affine(),
            ],
            &[setup.pk.g2, setup.pk.x_g2],
        );
        if computed_signature_commitment != proof.signature_commitment {
            return Ok(false);
        }

        // Prepare bases for verification
        let hidden_bases_g2: Vec<E::G2Affine> = setup
            .pk
            .y_g2
            .iter()
            .enumerate()
            .filter(|&(i, _)| !proof.disclosed_messages.iter().any(|&(j, _)| i == j))
            .map(|(_, &base)| base)
            .chain(std::iter::once(setup.pk.g2)) // Add g2 for tt
            .collect();

        let bases_g1 = Helpers::copy_point_to_length_g1::<E>(
            proof.randomized_signature.0,
            &hidden_bases_g2.len(),
        );

        // Verify Schnorr proof
        let is_schnorr_valid = SchnorrProtocolPairing::verify(
            &proof.schnorr_commitment,
            &proof.witness_commitment,
            &proof.challenge,
            &bases_g1,
            &hidden_bases_g2,
            &proof.responses,
        );

        if !is_schnorr_valid {
            return Ok(false);
        }

        // Compute disclosed messages commitment
        let disclosed_bases_g2: Vec<E::G2Affine> = proof
            .disclosed_messages
            .iter()
            .map(|&(i, _)| setup.pk.y_g2[i])
            .collect();
        let disclosed_messages: Vec<E::ScalarField> =
            proof.disclosed_messages.iter().map(|&(_, m)| m).collect();
        let sigma_1_vector = Helpers::copy_point_to_length_g1::<E>(
            proof.randomized_signature.0,
            &disclosed_messages.len(),
        );
        let disclosed_m_scaled_g1 = Helpers::compute_scaled_points_g1::<E>(
            None,
            None,
            &disclosed_messages,
            &sigma_1_vector,
        );
        let disclosed_messages_gt =
            Helpers::compute_gt::<E>(&disclosed_m_scaled_g1, &disclosed_bases_g2);

        // Final verification
        let public_and_private_gt = proof.witness_commitment + disclosed_messages_gt;
        Ok(public_and_private_gt == proof.signature_commitment)
    }

    // // Equality Proof (when you implement it)
    // pub fn prove_equality<E: Pairing>(
    //     setup: &PSTestSetup<E>,
    //     equality_indices: &[usize],
    // ) -> Vec<u8> {
    //     // Implementation...
    // }

    // pub fn verify_equality<E: Pairing>(
    //     setup: &PSTestSetup<E>,
    //     serialized_proof: &[u8],
    //     equality_indices: &[usize],
    // ) -> bool {
    //     // Implementation...
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::create_ps_test_setup;
    use ark_bls12_381::Bls12_381;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn test_prove_and_verify_knowledge() {
        let setup = create_ps_test_setup::<Bls12_381>(6);
        let proof = PSProofs::prove_knowledge(&setup);
        assert!(PSProofs::verify_knowledge(&setup, &proof));
    }

    #[test]
    fn test_selective_disclosure() {
        // Create a deterministic RNG for reproducibility
        let mut rng = StdRng::seed_from_u64(12345);

        // Setup
        let message_count = 5; // 5 messages + 1 for tt
        let setup = create_ps_test_setup::<Bls12_381>(message_count);

        // Choose indices to disclose (e.g., disclose messages at index 1 and 3)
        let disclosed_indices = vec![1, 3];

        // Generate the proof
        let proof = PSProofs::prove_selective_disclosure(&setup, &disclosed_indices, &mut rng)
            .expect("Proof generation should succeed");

        // Verify the proof
        let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
            .expect("Proof verification should complete");

        assert!(is_valid, "Selective disclosure proof should be valid");

        // Test with invalid proof
        // let mut tampered_proof = proof.clone();
        // tampered_proof[0] ^= 1; // Flip a bit in the proof
        // let is_invalid = PSProofs::verify_selective_disclosure(&setup, &tampered_proof)
        //     .expect("Tampered proof verification should complete");

        // assert!(!is_invalid, "Tampered proof should be invalid");

        // // Test with invalid disclosed indices
        // let invalid_indices = vec![message_count]; // This index is out of bounds
        // let result = PSProofs::prove_selective_disclosure(&setup, &invalid_indices, &mut rng);
        // assert!(
        //     result.is_err(),
        //     "Proof generation should fail with invalid indices"
        // );

        // // Test disclosing all messages
        // let all_indices: Vec<usize> = (0..message_count).collect();
        // let result = PSProofs::prove_selective_disclosure(&setup, &all_indices, &mut rng);
        // assert!(result.is_ok(), "Should be able to disclose all messages");

        // // Test disclosing no messages
        // let no_indices: Vec<usize> = vec![];
        // let proof = PSProofs::prove_selective_disclosure(&setup, &no_indices, &mut rng)
        //     .expect("Should be able to generate proof with no disclosed messages");
        // let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
        //     .expect("Should be able to verify proof with no disclosed messages");
        // assert!(is_valid, "Proof with no disclosed messages should be valid");
    }
}
