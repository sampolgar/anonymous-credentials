// use crate::test_helpers::BBSPlusTestSetup;
// use ark_ec::pairing::{Pairing, PairingOutput};
// use ark_ec::{AffineRepr, CurveGroup};
// use ark_ff::UniformRand;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::ops::Neg;
// use schnorr::schnorr::SchnorrProtocol;
// use thiserror::Error;
// use utils::helpers::Helpers;

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct SelectiveDisclosureProof<E: Pairing> {
//     pub randomized_signature: (E::G1Affine, E::G1Affine),
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

//         // Randomize signature
//         let r = E::ScalarField::rand(&mut rng);
//         let randomized_signature = setup.signature.randomize(pk, &mut rng, &messages);

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
//                 .map(|&(i, _)| setup.pk.h[i])
//                 .collect::<Vec<_>>(),
//         );

//         // Generate Schnorr proof
//         let bases: Vec<E::G1Affine> = std::iter::once(setup.pk.g1)
//             .chain(
//                 hidden_messages
//                     .iter()
//                     .map(|&(i, _)| setup.pk.h[i])
//                     .collect::<Vec<_>>(),
//             )
//             .collect();

//         let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);
//         let challenge = E::ScalarField::rand(&mut rng);

//         let mut scalars = vec![r];
//         scalars.extend(hidden_messages.iter().map(|&(_, m)| m));

//         let responses = SchnorrProtocol::prove(&schnorr_commitment, &scalars, &challenge);

//         let proof = SelectiveDisclosureProof {
//             randomized_signature: (randomized_signature.a, randomized_signature.a_prime),
//             commitment,
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
//             .h
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
//             .map(|&(i, m)| setup.pk.h[i].mul(m))
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
