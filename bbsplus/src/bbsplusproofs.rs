// use crate::signature::RandomizedSignature;
// use crate::test_helpers::BBSPlusTestSetup;
// use ark_ec::pairing::{Pairing, PairingOutput};
// use ark_ec::{AffineRepr, CurveGroup};
// use ark_ff::UniformRand;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::{ops::Neg, One};
// use schnorr::schnorr::SchnorrProtocol;
// use thiserror::Error;
// use utils::helpers::Helpers;

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct SelectiveDisclosureProof<E: Pairing> {
//     pub randomized_signature: RandomizedSignature<E>,
//     pub commitment: E::G1Affine,
//     pub schnorr_commitment: E::G1Affine,
//     pub challenge: E::ScalarField,
//     pub responses: Vec<E::ScalarField>,
//     pub disclosed_messages: Vec<(usize, E::ScalarField)>,
// }

// #[derive(Error, Debug)]
// pub enum ProofError {
//     #[error("Invalid disclosed index")]
//     InvalidDisclosedIndex,
//     #[error("Too many disclosed indices")]
//     TooManyDisclosedIndices,
//     #[error("Serialization error: {0}")]
//     SerializationError(#[from] ark_serialize::SerializationError),
// }

// pub struct BBSPlusProofs;

// impl BBSPlusProofs {
//     pub fn prove_selective_disclosure<E: Pairing>(
//         setup: &BBSPlusTestSetup<E>,
//         disclosed_indices: &[usize],
//     ) -> Result<Vec<u8>, ProofError> {
//         let mut rng = ark_std::test_rng();

//         // Validate indices
//         if disclosed_indices.iter().any(|&i| i >= setup.messages.len()) {
//             return Err(ProofError::InvalidDisclosedIndex);
//         }
//         if disclosed_indices.len() > setup.messages.len() {
//             return Err(ProofError::TooManyDisclosedIndices);
//         }

//         // Use the randomized signature from the setup
//         let randomized_signature = setup.randomized_signature.clone();

//         // Split messages into disclosed and hidden
//         let (disclosed_messages, hidden_messages): (Vec<_>, Vec<_>) = setup
//             .messages
//             .iter()
//             .enumerate()
//             .partition(|&(i, _)| disclosed_indices.contains(&i));

//         // Compute commitment
//         let commitment = Helpers::compute_commitment_g1::<E>(
//             &r,
//             &setup.pk.g1,
//             &hidden_messages.iter().map(|&(_, m)| *m).collect::<Vec<_>>(),
//             &hidden_messages
//                 .iter()
//                 .map(|&(i, _)| setup.pk.h_l[i])
//                 .collect::<Vec<_>>(),
//         );

//         // Generate Schnorr proof
//         let bases: Vec<E::G1Affine> = std::iter::once(setup.pk.g1)
//             .chain(
//                 hidden_messages
//                     .iter()
//                     .map(|&(i, _)| setup.pk.h_l[i])
//                     .collect::<Vec<_>>(),
//             )
//             .collect();

//         let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);
//         let challenge = E::ScalarField::rand(&mut rng);

//         let mut scalars = vec![r];
//         scalars.extend(hidden_messages.iter().map(|&(_, m)| m));

//         let responses = SchnorrProtocol::prove(&schnorr_commitment, &scalars, &challenge);

//         let proof = SelectiveDisclosureProof::<E> {
//             randomized_signature: commitment,
//             schnorr_commitment: schnorr_commitment.com_t,
//             challenge,
//             responses: responses.0,
//             disclosed_messages: disclosed_messages
//                 .into_iter()
//                 .map(|(i, &m)| (i, m))
//                 .collect(),
//         };

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     pub fn verify_selective_disclosure<E: Pairing>(
//         setup: &BBSPlusTestSetup<E>,
//         serialized_proof: &[u8],
//     ) -> Result<bool, ProofError> {
//         let proof: SelectiveDisclosureProof<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

//         // Verify the signature
//         let computed_commitment = Helpers::compute_commitment_g1::<E>(
//             &E::ScalarField::one(),
//             &proof.randomized_signature.0,
//             &[],
//             &[proof.randomized_signature.1],
//         );

//         if computed_commitment != proof.commitment {
//             return Ok(false);
//         }

//         // Prepare bases for Schnorr verification
//         let hidden_bases: Vec<E::G1Affine> = setup
//             .pk
//             .h_l
//             .iter()
//             .enumerate()
//             .filter(|&(i, _)| !proof.disclosed_messages.iter().any(|&(j, _)| i == j))
//             .map(|(_, &base)| base)
//             .collect();

//         let bases = std::iter::once(setup.pk.g1)
//             .chain(hidden_bases.into_iter())
//             .collect::<Vec<_>>();

//         // Verify Schnorr proof
//         let is_schnorr_valid = SchnorrProtocol::verify(
//             &bases,
//             &proof.commitment,
//             &proof.schnorr_commitment,
//             &proof.responses,
//             &proof.challenge,
//         );

//         if !is_schnorr_valid {
//             return Ok(false);
//         }

//         // Verify the pairing equation
//         let disclosed_product = proof
//             .disclosed_messages
//             .iter()
//             .map(|&(i, m)| setup.pk.h_l[i].mul(m))
//             .sum::<E::G1>();

//         let lhs = E::pairing(
//             proof.randomized_signature.0 + disclosed_product.into_affine(),
//             setup.pk.w,
//         );
//         let rhs = E::pairing(proof.randomized_signature.1, setup.pk.g2);

//         Ok(lhs == rhs)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::test_helpers::create_bbs_plus_test_setup;
//     use ark_bls12_381::Bls12_381;

//     #[test]
//     fn test_selective_disclosure() {
//         let message_count = 5;
//         let setup = create_bbs_plus_test_setup::<Bls12_381>(message_count);

//         let disclosed_indices = vec![1, 3];

//         let proof = BBSPlusProofs::prove_selective_disclosure(&setup, &disclosed_indices)
//             .expect("Proof generation should succeed");

//         let is_valid = BBSPlusProofs::verify_selective_disclosure(&setup, &proof)
//             .expect("Proof verification should complete");

//         assert!(is_valid, "Selective disclosure proof should be valid");

//         // Additional tests for edge cases...
//     }
// }

use crate::keygen;
use crate::signature::{RandomizedSignature, Signature};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use thiserror::Error;
use utils::helpers::Helpers;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid disclosed index")]
    InvalidDisclosedIndex,
    #[error("Too many disclosed indices")]
    TooManyDisclosedIndices,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Invalid equality index")]
    InvalidEqualityIndex,
    #[error("No equality indices provided")]
    NoEqualityIndices,
}

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct SelectiveDisclosureProof<E: Pairing> {
//     pub randomized_signature: RandomizedSignature<E>,
//     pub commitment: E::G1Affine,
//     pub schnorr_commitment: E::G1Affine,
//     pub challenge: E::ScalarField,
//     pub responses: Vec<E::ScalarField>,
//     pub disclosed_messages: Vec<(usize, E::ScalarField)>,
// }

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SelectiveDisclosureProof<E: Pairing> {
    pub randomized_signature: RandomizedSignature<E>,
    pub schnorr_commitment_1: E::G1Affine,
    pub schnorr_responses_1: Vec<E::ScalarField>,
    pub schnorr_commitment_2: E::G1Affine,
    pub schnorr_responses_2: Vec<E::ScalarField>,
    pub challenge: E::ScalarField,
    pub disclosed_messages: Vec<(usize, E::ScalarField)>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualityProof<E: Pairing> {
    pub randomized_signature: RandomizedSignature<E>,
    pub commitment: E::G1Affine,
    pub schnorr_commitment: E::G1Affine,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
    pub equality_indices: Vec<usize>,
}

pub struct BBSPlusProofs;

impl BBSPlusProofs {
    pub fn prove_knowledge<E: Pairing, R: Rng>(
        signature: &Signature<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Prove knowledge of all messages by calling prove_selective_disclosure with no disclosed indices
        Self::prove_selective_disclosure(signature, pk, messages, &[], rng)
    }

    // pub fn verify_knowledge<E: Pairing>(
    //     pk: &keygen::PublicKey<E>,
    //     proof: &[u8],
    // ) -> Result<bool, ProofError> {
    //     // Verify knowledge of all messages by calling verify_selective_disclosure with no disclosed messages
    //     Self::verify_selective_disclosure(pk, proof, &[])
    // }

    pub fn prove_selective_disclosure<E: Pairing, R: Rng>(
        signature: &Signature<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        disclosed_indices: &[usize],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Validate indices
        if disclosed_indices.iter().any(|&i| i >= messages.len()) {
            return Err(ProofError::InvalidDisclosedIndex);
        }
        if disclosed_indices.len() > messages.len() {
            return Err(ProofError::TooManyDisclosedIndices);
        }

        // Randomize the signature
        let randomized_sig = signature.prepare_for_proof(pk, messages, rng);

        // Split messages into disclosed and hidden
        let (disclosed_messages, hidden_messages): (Vec<_>, Vec<_>) = messages
            .iter()
            .enumerate()
            .partition(|&(i, _)| disclosed_indices.contains(&i));

        // 2. Prove knowledge of -e, r2 such that Ābar/d = A'^-e · h0^r2
        let bases_1 = vec![randomized_sig.a_prime, pk.h0];
        let exponents_1 = vec![randomized_sig.e.neg(), randomized_sig.r2];
        let public_statement_1 = (randomized_sig
            .a_bar
            .add(randomized_sig.d.into_group().neg()))
        .into_affine();

        let challenge = E::ScalarField::rand(rng);

        let schnorr_commitment_1 = SchnorrProtocol::commit(&bases_1, rng);
        let schnorr_responses_1 =
            SchnorrProtocol::prove(&schnorr_commitment_1, &exponents_1, &challenge);

        // this can be deleted, this is a test to see if it works before creating prover/verifier
        let proof_1_test = SchnorrProtocol::verify(
            &bases_1,
            &public_statement_1,
            &schnorr_commitment_1,
            &schnorr_responses_1,
            &challenge,
        );

        assert!(proof_1_test, "proof 1 test isn't valid!");

        // 3. Prove g1 * \prod_{i \in D}h_i^m_i = d^r3 * h_0^{-s'} * \prod_{i \notin D} hi^-mi
        let mut disclosed_product = pk.g1.into_group();
        for &i in disclosed_indices {
            disclosed_product += pk.h_l[i].mul(messages[i]);
        }
        let public_statement_2 = disclosed_product.into_affine();

        // into_group().neg().into_affine() seems like an inefficient way to do this, will leave it for now
        // the bases need to be negative to take care of the balancing equation
        let mut bases_2 = vec![randomized_sig.d, pk.h0.into_group().neg().into_affine()];
        let mut exponents_2 = vec![randomized_sig.r3, randomized_sig.s_prime];

        for (i, &message) in messages.iter().enumerate() {
            if !disclosed_indices.contains(&i) {
                bases_2.push(pk.h_l[i].into_group().neg().into_affine());
                exponents_2.push(message);
            }
        }

        let schnorr_commitment_2 = SchnorrProtocol::commit(&bases_2, rng);
        let schnorr_responses_2 =
            SchnorrProtocol::prove(&schnorr_commitment_2, &exponents_2, &challenge);

        // Verify the second proof (this can be removed in production)
        let proof_2_valid = SchnorrProtocol::verify(
            &bases_2,
            &public_statement_2,
            &schnorr_commitment_2,
            &schnorr_responses_2,
            &challenge,
        );
        assert!(proof_2_valid, "Proof 2 is not valid!");

        // Construct the proof
        let proof = SelectiveDisclosureProof {
            randomized_signature: randomized_sig,
            schnorr_commitment_1: schnorr_commitment_1.com_t,
            schnorr_responses_1: schnorr_responses_1.0,
            schnorr_commitment_2: schnorr_commitment_2.com_t,
            schnorr_responses_2: schnorr_responses_2.0,
            challenge,
            disclosed_messages: disclosed_indices
                .iter()
                .map(|&i| (i, messages[i]))
                .collect(),
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    // pub fn verify_selective_disclosure<E: Pairing>(
    //     pk: &keygen::PublicKey<E>,
    //     proof: &[u8],
    //     disclosed_messages: &[(usize, E::ScalarField)],
    // ) -> Result<bool, ProofError> {
    //     let proof: SelectiveDisclosureProof<E> =
    //         CanonicalDeserialize::deserialize_compressed(proof)?;

    //     // Verify the randomized signature
    //     if !proof.randomized_signature.verify_pairing(pk) {
    //         return Ok(false);
    //     }

    //     // Prepare bases for Schnorr verification
    //     let hidden_bases: Vec<E::G1Affine> = pk
    //         .h_l
    //         .iter()
    //         .enumerate()
    //         .filter(|&(i, _)| !disclosed_messages.iter().any(|&(j, _)| i == j))
    //         .map(|(_, &base)| base)
    //         .collect();

    //     let bases = std::iter::once(pk.g1)
    //         .chain(hidden_bases.into_iter())
    //         .collect::<Vec<_>>();

    //     // Verify Schnorr proof
    //     let is_schnorr_valid = SchnorrProtocol::verify(
    //         &bases,
    //         &proof.commitment,
    //         &proof.schnorr_commitment,
    //         &proof.responses,
    //         &proof.challenge,
    //     );

    //     if !is_schnorr_valid {
    //         return Ok(false);
    //     }

    //     // Verify the pairing equation
    //     let disclosed_product = disclosed_messages
    //         .iter()
    //         .map(|&(i, m)| pk.h_l[i].mul(m))
    //         .sum::<E::G1>();

    //     let lhs = E::pairing(
    //         proof.randomized_signature.a_prime + disclosed_product.into_affine(),
    //         pk.w,
    //     );
    //     let rhs = E::pairing(proof.randomized_signature.a_bar, pk.g2);

    //     Ok(lhs == rhs)
    // }

    // pub fn prove_equality<E: Pairing, R: Rng>(
    //     signature: &Signature<E>,
    //     pk: &keygen::PublicKey<E>,
    //     messages: &[E::ScalarField],
    //     equality_indices: &[usize],
    //     rng: &mut R,
    // ) -> Result<Vec<u8>, ProofError> {
    //     // Implementation to be added...
    // }

    // pub fn verify_equality<E: Pairing>(
    //     pk: &keygen::PublicKey<E>,
    //     proof: &[u8],
    //     equality_indices: &[usize],
    // ) -> Result<bool, ProofError> {
    //     // Implementation to be added...
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use ark_bls12_381::Bls12_381;

    // Add test functions here
}
