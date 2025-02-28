// use crate::test_helpers::PSTestSetup;
// use ark_ec::pairing::{Pairing, PairingOutput};
// use ark_ec::{AffineRepr, CurveGroup};
// use ark_ff::UniformRand;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::ops::Neg;
// use schnorr::schnorr_pairing::SchnorrProtocolPairing;
// // use schnorr::schnorr_pairing::{SchnorrCommitment, SchnorrProtocolPairing};
// use thiserror::Error;
// use utils::helpers::Helpers;

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct ProofOfKnowledge<E: Pairing> {
//     pub randomized_signature: (E::G1Affine, E::G1Affine),
//     pub signature_commitment: PairingOutput<E>,
//     pub schnorr_commitment: PairingOutput<E>,
//     pub challenge: E::ScalarField,
//     pub responses: Vec<E::ScalarField>,
// }

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct SelectiveDisclosureProof<E: Pairing> {
//     pub randomized_signature: (E::G1Affine, E::G1Affine),
//     pub signature_commitment: PairingOutput<E>,
//     pub witness_commitment: PairingOutput<E>,
//     pub schnorr_commitment: PairingOutput<E>,
//     pub challenge: E::ScalarField,
//     pub responses: Vec<E::ScalarField>,
//     pub disclosed_messages: Vec<(usize, E::ScalarField)>,
// }

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct EqualityProof<E: Pairing> {
//     pub randomized_signature: (E::G1Affine, E::G1Affine),
//     pub signature_commitment: PairingOutput<E>,
//     pub schnorr_commitment: PairingOutput<E>,
//     pub witness_commitment: PairingOutput<E>,
//     pub challenge: E::ScalarField,
//     pub responses: Vec<E::ScalarField>,
//     pub equality_blindings: Vec<E::ScalarField>,
// }

// /// Proof of knowledge of a commitment in the G1 group
// // #[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
// // pub struct CommitmentProof<E: Pairing> {
// //     pub commitment: E::G1Affine,
// //     pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
// //     pub bases: Vec<E::G1Affine>,
// //     pub challenge: E::ScalarField,
// //     pub responses: Vec<E::ScalarField>,
// // }
// #[derive(Error, Debug)]
// pub enum ProofError {
//     #[error("Invalid disclosed index")]
//     InvalidDisclosedIndex,
//     #[error("Too many disclosed indices")]
//     TooManyDisclosedIndices,
//     #[error("Serialization error: {0}")]
//     SerializationError(#[from] ark_serialize::SerializationError),
//     #[error("Invalid equality index")]
//     InvalidEqualityIndex,
//     #[error("No equality indices provided")]
//     NoEqualityIndices,
//     #[error("No equality checks provided")]
//     NoEqualityChecks,
//     #[error("Invalid proof")]
//     InvalidProof,
// }

// pub struct PSProofs;

// impl PSProofs {
//     // pub fn pok_commitment_prove<E: Pairing>(
//     //     commitment: E::G1Affine,
//     // ) -> Result<Vec<u8>, ProofError> {
//     //     let mut rng = ark_std::test_rng();

//     //     // Get bases and exponents for the proof
//     //     let bases = commitment.pp.get_g1_bases();
//     //     let exponents = commitment.get_exponents();

//     //     // Generate Schnorr commitment
//     //     let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

//     //     // Generate challenge
//     //     let challenge = E::ScalarField::rand(&mut rng);

//     //     // Generate responses
//     //     let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

//     //     // Create and serialize proof with explicit type annotation
//     //     let proof: CommitmentProof<E> = CommitmentProof {
//     //         commitment: commitment.cmg1,
//     //         schnorr_commitment,
//     //         bases,
//     //         challenge,
//     //         responses: responses.0,
//     //     };

//     //     let mut serialized_proof = Vec::new();
//     //     proof.serialize_compressed(&mut serialized_proof)?;

//     //     Ok(serialized_proof)
//     // }

//     pub fn prove_knowledge<E: Pairing>(setup: &PSTestSetup<E>) -> Vec<u8> {
//         let mut rng = ark_std::test_rng();
//         let t = E::ScalarField::rand(&mut rng);
//         let sigma_prime = setup.signature.randomize_for_pok_new(&mut rng, &t);

//         // Generate a commitment to the signature
//         let signature_commitment_gt = sigma_prime.generate_commitment_gt(&setup.pk);

//         // Generate commitment to secret exponents tt, m1, ... ,mn
//         let base_length = setup.messages.len() + 1;
//         let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &base_length);
//         let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

//         let schnorr_commitment_gt =
//             SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);

//         let challenge = E::ScalarField::rand(&mut rng);

//         // generate message vector
//         let m_vector = Helpers::add_scalar_to_vector::<E>(&t, &setup.messages);
//         let responses =
//             SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &m_vector, &challenge);

//         let proof = ProofOfKnowledge {
//             randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
//             signature_commitment: signature_commitment_gt,
//             schnorr_commitment: schnorr_commitment_gt.t_com,
//             challenge,
//             responses: responses.0,
//         };

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof).unwrap();
//         // proof.serialize(&mut serialized_proof).unwrap();
//         serialized_proof
//     }

//     pub fn verify_knowledge<E: Pairing>(setup: &PSTestSetup<E>, serialized_proof: &[u8]) -> bool {
//         let proof: ProofOfKnowledge<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof).unwrap();

//         let computed_signature_commitment = Helpers::compute_gt::<E>(
//             &[
//                 proof.randomized_signature.1,
//                 proof
//                     .randomized_signature
//                     .0
//                     .into_group()
//                     .neg()
//                     .into_affine(),
//             ],
//             &[setup.pk.g2, setup.pk.x_g2],
//         );

//         assert_eq!(
//             computed_signature_commitment, proof.signature_commitment,
//             "must be equal"
//         );

//         // 2. Prepare bases for verification
//         let base_length = setup.messages.len() + 1;
//         let bases_g1 =
//             Helpers::copy_point_to_length_g1::<E>(proof.randomized_signature.0, &base_length);
//         let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

//         // 3. Verify the Schnorr proof
//         let is_valid = SchnorrProtocolPairing::verify(
//             &proof.schnorr_commitment,
//             &proof.signature_commitment,
//             &proof.challenge,
//             &bases_g1,
//             &bases_g2,
//             &proof.responses,
//         );

//         assert_eq!(
//             proof.responses.len(),
//             base_length,
//             "responses and base length don't match"
//         );

//         is_valid
//     }

//     pub fn prove_selective_disclosure<E: Pairing>(
//         setup: &PSTestSetup<E>,
//         disclosed_indices: &[usize],
//     ) -> Result<Vec<u8>, ProofError> {
//         let message_count = setup.messages.len() - 1; //-1 for t?
//         if disclosed_indices.iter().any(|&i| i >= setup.messages.len()) {
//             return Err(ProofError::InvalidDisclosedIndex);
//         }
//         if disclosed_indices.len() > setup.messages.len() {
//             return Err(ProofError::TooManyDisclosedIndices);
//         }
//         // randomize signature
//         let mut rng = ark_std::test_rng();
//         let t = E::ScalarField::rand(&mut rng);
//         let sigma_prime = setup.signature.randomize_for_pok_new(&mut rng, &t);
//         // Generate signature commitment
//         let signature_commitment = Helpers::compute_gt::<E>(
//             &[
//                 sigma_prime.sigma2,
//                 sigma_prime.sigma1.into_group().neg().into_affine(),
//             ],
//             &[setup.pk.g2, setup.pk.x_g2],
//         );

//         // Split messages into disclosed and hidden
//         let mut disclosed_messages = vec![];
//         let mut hidden_messages = vec![];
//         let mut hidden_bases_g2 = vec![];

//         for (i, m) in setup.messages.iter().enumerate() {
//             print!("i: {}, message_count: {}", i, message_count);
//             if disclosed_indices.contains(&i) {
//                 disclosed_messages.push((i, *m));
//             } else {
//                 hidden_messages.push(*m);
//                 hidden_bases_g2.push(setup.pk.y_g2[i]);
//             }
//         }
//         // add t and g2 to the end of the vectors
//         hidden_messages.push(t);
//         hidden_bases_g2.push(setup.pk.g2);

//         // Commit to hidden messages. Which includes [m1, m2,...tt], hidden bases [y1, y2,...g]
//         let bases_g1 =
//             Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &hidden_bases_g2.len());

//         let witness_commitment_hidden_values = Helpers::compute_gt_from_g1_g2_scalars::<E>(
//             &bases_g1,
//             &hidden_bases_g2,
//             &hidden_messages,
//         );

//         // Generate Schnorr commitment
//         let schnorr_commitment_hidden_values =
//             SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &hidden_bases_g2, &mut rng);

//         // Generate challenge
//         let challenge = E::ScalarField::rand(&mut rng);

//         // Generate responses
//         let responses = SchnorrProtocolPairing::prove(
//             &schnorr_commitment_hidden_values,
//             &hidden_messages,
//             &challenge,
//         );
//         // println!(
//         //     "responseslen: {}, baseslen: {}",
//         //     responses.0.len(),
//         //     bases_g1.len()
//         // );

//         // println!("Bases G1:");
//         // for base in &bases_g1 {
//         //     println!("{:?}", base);
//         // }

//         // println!("Hidden Bases G2:");
//         // for base in &hidden_bases_g2 {
//         //     println!("{:?}", base);
//         // }

//         // println!("Responses:");
//         // for response in &responses.0 {
//         //     println!("{:?}", response);
//         // }

//         let is_valid = SchnorrProtocolPairing::verify(
//             &schnorr_commitment_hidden_values.t_com,
//             &witness_commitment_hidden_values,
//             &challenge,
//             &bases_g1,
//             &hidden_bases_g2,
//             &responses.0,
//         );

//         assert!(is_valid, "initial verification isn't valid");

//         // Create and serialize the proof
//         let proof = SelectiveDisclosureProof::<E> {
//             randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
//             signature_commitment,
//             witness_commitment: witness_commitment_hidden_values,
//             schnorr_commitment: schnorr_commitment_hidden_values.t_com,
//             challenge,
//             responses: responses.0,
//             disclosed_messages,
//         };
//         println!("initial verification is valid");

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     pub fn verify_selective_disclosure<E: Pairing>(
//         setup: &PSTestSetup<E>,
//         serialized_proof: &[u8],
//     ) -> Result<bool, ProofError> {
//         let proof: SelectiveDisclosureProof<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

//         // Verify signature commitment
//         let computed_signature_commitment = Helpers::compute_gt::<E>(
//             &[
//                 proof.randomized_signature.1,
//                 proof
//                     .randomized_signature
//                     .0
//                     .into_group()
//                     .neg()
//                     .into_affine(),
//             ],
//             &[setup.pk.g2, setup.pk.x_g2],
//         );

//         if computed_signature_commitment != proof.signature_commitment {
//             return Ok(false);
//         }
//         println!("computed sig commitment is ok");

//         // Prepare bases for verification
//         let hidden_bases_g2: Vec<E::G2Affine> = setup
//             .pk
//             .y_g2
//             .iter()
//             .enumerate()
//             .filter(|&(i, _)| !proof.disclosed_messages.iter().any(|&(j, _)| i == j))
//             .map(|(_, &base)| base)
//             .chain(std::iter::once(setup.pk.g2)) // Add g2 for tt
//             .collect();

//         let bases_g1 = Helpers::copy_point_to_length_g1::<E>(
//             proof.randomized_signature.0,
//             &hidden_bases_g2.len(),
//         );

//         // Verify Schnorr proof. This should verify as a proof of knowledge of the hidden values
//         // println!("Bases G1 mk2:");
//         // for base in &bases_g1 {
//         //     println!("{:?}", base);
//         // }

//         // println!("Hidden Bases G2 mk2:");
//         // for base in &hidden_bases_g2 {
//         //     println!("{:?}", base);
//         // }

//         // println!("Responses mk2:");
//         // for response in &proof.responses {
//         //     println!("{:?}", response);
//         // }

//         let is_schnorr_valid = SchnorrProtocolPairing::verify(
//             &proof.schnorr_commitment,
//             &proof.witness_commitment,
//             &proof.challenge,
//             &bases_g1,
//             &hidden_bases_g2,
//             &proof.responses,
//         );

//         if !is_schnorr_valid {
//             println!("schnorr is not valid");
//             return Ok(false);
//         }
//         println!("schnorr is valid");

//         // Compute disclosed messages commitment
//         let disclosed_bases_g2: Vec<E::G2Affine> = proof
//             .disclosed_messages
//             .iter()
//             .map(|&(i, _)| setup.pk.y_g2[i])
//             .collect();
//         let disclosed_messages: Vec<E::ScalarField> =
//             proof.disclosed_messages.iter().map(|&(_, m)| m).collect();
//         let sigma_1_vector = Helpers::copy_point_to_length_g1::<E>(
//             proof.randomized_signature.0,
//             &disclosed_messages.len(),
//         );
//         let disclosed_m_scaled_g1 = Helpers::compute_scaled_points_g1::<E>(
//             None,
//             None,
//             &disclosed_messages,
//             &sigma_1_vector,
//         );
//         let disclosed_messages_gt =
//             Helpers::compute_gt::<E>(&disclosed_m_scaled_g1, &disclosed_bases_g2);

//         // Final verification
//         let public_and_private_gt = proof.witness_commitment + disclosed_messages_gt;
//         Ok(public_and_private_gt == proof.signature_commitment)
//     }

//     // takes in vector of equality checks [(arrayIndex, message),(.,.)]
//     pub fn prove_equality<E: Pairing>(
//         setup: &PSTestSetup<E>,
//         equality_checks: &[(usize, E::ScalarField)],
//     ) -> Result<Vec<u8>, ProofError> {
//         let mut rng = ark_std::test_rng();

//         if equality_checks.is_empty() {
//             return Err(ProofError::NoEqualityChecks);
//         }
//         if equality_checks
//             .iter()
//             .any(|&(i, _)| i >= setup.messages.len())
//         {
//             return Err(ProofError::InvalidEqualityIndex);
//         }

//         let t = E::ScalarField::rand(&mut rng);
//         let sigma_prime = setup.signature.randomize_for_pok_new(&mut rng, &t);

//         // Generate a commitment to the signature
//         let signature_commitment_gt = sigma_prime.generate_commitment_gt(&setup.pk);
//         let base_length = setup.messages.len() + 1;
//         let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &base_length);
//         let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);
//         let schnorr_commitment_gt =
//             SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);
//         let challenge = E::ScalarField::rand(&mut rng);

//         // generate message vector
//         let m_vector = Helpers::add_scalar_to_vector::<E>(&t, &setup.messages);
//         // generate witness commitment
//         let witness_commitment_gt =
//             Helpers::compute_gt_from_g1_g2_scalars::<E>(&bases_g1, &bases_g2, &m_vector);

//         let responses =
//             SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &m_vector, &challenge);

//         // Test Schnorr verification
//         let is_schnorr_valid = SchnorrProtocolPairing::verify(
//             &schnorr_commitment_gt.t_com,
//             &witness_commitment_gt,
//             &challenge,
//             &bases_g1,
//             &bases_g2,
//             &responses.0,
//         );
//         assert!(
//             is_schnorr_valid,
//             "Schnorr verification failed in prove_equality"
//         );

//         // create a new vector of messages with blindings
//         let equality_blindings: Vec<E::ScalarField> = schnorr_commitment_gt
//             .blindings
//             .iter()
//             .enumerate()
//             .filter_map(|(i, &blinding)| {
//                 if equality_checks.iter().any(|&(index, _)| index == i) {
//                     Some(blinding)
//                 } else {
//                     None
//                 }
//             })
//             .collect();

//         let proof = EqualityProof {
//             randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
//             signature_commitment: signature_commitment_gt,
//             schnorr_commitment: schnorr_commitment_gt.t_com,
//             witness_commitment: witness_commitment_gt,
//             challenge,
//             responses: responses.0,
//             equality_blindings,
//         };

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     pub fn verify_equality<E: Pairing>(
//         setup: &PSTestSetup<E>,
//         serialized_proof: &[u8],
//         equality_checks: &[(usize, E::ScalarField)],
//     ) -> Result<bool, ProofError> {
//         let mut rng = ark_std::test_rng();
//         let proof: EqualityProof<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof)?;
//         // Verify signature commitment
//         let computed_signature_commitment = Helpers::compute_gt::<E>(
//             &[
//                 proof.randomized_signature.1,
//                 proof
//                     .randomized_signature
//                     .0
//                     .into_group()
//                     .neg()
//                     .into_affine(),
//             ],
//             &[setup.pk.g2, setup.pk.x_g2],
//         );

//         if computed_signature_commitment != proof.signature_commitment {
//             return Ok(false);
//         }

//         let base_length = setup.messages.len() + 1;
//         let bases_g1 =
//             Helpers::copy_point_to_length_g1::<E>(proof.randomized_signature.0, &base_length);
//         let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

//         // Verify Signature Proof
//         // 3. Verify the Schnorr proof
//         let is_valid = SchnorrProtocolPairing::verify(
//             &proof.schnorr_commitment,
//             &proof.signature_commitment,
//             &proof.challenge,
//             &bases_g1,
//             &bases_g2,
//             &proof.responses,
//         );

//         // Verify equality proofs
//         // commit to equality messages with the same randomization factor and generator
//         let equality_messages: Vec<E::ScalarField> = equality_checks
//             .iter()
//             .map(|&(_, message)| message)
//             .collect();

//         let mut equality_bases_g1 = Vec::<E::G1Affine>::new();
//         let mut equality_bases_g2 = Vec::<E::G2Affine>::new();

//         for (i, _) in equality_checks.iter() {
//             equality_bases_g1.push(proof.randomized_signature.0);
//             equality_bases_g2.push(setup.pk.y_g2[*i]);
//         }

//         let equality_commitment = SchnorrProtocolPairing::commit_with_prepared_blindness::<E, _>(
//             &equality_bases_g1,
//             &equality_bases_g2,
//             &proof.equality_blindings,
//             &mut rng,
//         );

//         let equality_responses = SchnorrProtocolPairing::prove(
//             &equality_commitment,
//             &equality_messages,
//             &proof.challenge,
//         );

//         for response in &equality_responses.0 {
//             println!("equality repsonses:{:?}", response);
//         }

//         for (i, _) in equality_checks.iter() {
//             println!("proof responses: {:?}", proof.responses[*i]);
//         }

//         // first verify the responses are equal
//         for ((i, _), equality_response) in equality_checks.iter().zip(equality_responses.0.iter()) {
//             assert_eq!(
//                 equality_response, &proof.responses[*i],
//                 "Responses do not match at index {}",
//                 i
//             );
//         }

//         // I don't think this is needed but just to prove the opening of the commitment
//         let equality_witness_commitment_gt = Helpers::compute_gt_from_g1_g2_scalars::<E>(
//             &equality_bases_g1,
//             &equality_bases_g2,
//             &equality_messages,
//         );

//         let equality_valid = SchnorrProtocolPairing::verify(
//             &equality_commitment.t_com,
//             &equality_witness_commitment_gt,
//             &proof.challenge,
//             &equality_bases_g1,
//             &equality_bases_g2,
//             &equality_responses.0,
//         );

//         assert!(equality_valid, "equality not valid, equality proofs");
//         assert!(is_valid, "isvalid not valid, equality proofs");
//         // Ok(equality_valid);
//         Ok(is_valid)
//     }

//     // used for proving equality of messages between different signatures
//     // the PoK response should use the same randomness and challenge in all signatures
//     // this function takes in
//     // the id is always position 0
//     // setup: &PSTestSetup<E>,

//     // Proof of Knowledge
//     // In Short Randomizable Signatures Sec. 6.2, the pairing verification is
//     // e(sigma1', tilde_X) . \Sum e(sigma1', Y_j)^m_j . e(sigma1',tilde_g)^t = e(sigma2', tilde_g)
//     // we separate between LHS and RHS where LHS has exponents to prove, RHS doesn't
//     // LHS: \Sum e(sigma1', Y_j)^m_j . e(sigma1',tilde_g)^t  =  RHS: e(sigma2', tilde_g) / e(sigma1', tilde_X)

//     // Phase 0. Randomize Signature, compute RHS
//     //
//     // Phase 1. Prover Commitment           1. generate blindness, 2. commit to it with same bases
//     // Phase 2. Verifier Challenge
//     // Phase 3. Prover creates Responses    1.
//     pub fn prove_with_userid<E: Pairing>(
//         setup: &PSTestSetup<E>,
//         user_id_blindness: &E::ScalarField,
//         challenge: &E::ScalarField,
//     ) -> Result<Vec<u8>, ProofError> {
//         let mut rng = ark_std::test_rng();

//         //
//         // Sigma Protocol Phase 0
//         //
//         // randomize signature
//         let t = E::ScalarField::rand(&mut rng);
//         let sigma_prime = setup.signature.randomize_for_pok_new(&mut rng, &t);

//         // compute RHS e(sigma2', tilde_g) / e(sigma1', tilde_X)
//         let signature_commitment_gt = sigma_prime.generate_commitment_gt(&setup.pk);

//         //
//         // Sigma Protocol Phase 1 Commit
//         //
//         // Prepare T the Schnorr Initial Commitment with blinding factors
//         let base_length = setup.messages.len() + 1;
//         let mut prepared_blindness: Vec<E::ScalarField> = (0..base_length)
//             .map(|_| E::ScalarField::rand(&mut rng))
//             .collect();

//         // set position 0 to be user_id blindness - this should be equal for all signatures we want to prove equal
//         prepared_blindness[0] = *user_id_blindness;

//         // prepare for the GT bases that will be exponentiated
//         // Our Proof of Knowledge uses bases e(sigma1', Y_j)^m_j . e(sigma1',tilde_g)^t
//         // First, prepare a vector of sigma1' points for the g1 position
//         let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &base_length);

//         // prepare a vector of [Y_1, Y_2, ..., \tilde{}g] points
//         let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

//         // generate T, the iniital commitment sent in the first phase of Proof of Knowledge
//         let schnorr_commitment_gt = SchnorrProtocolPairing::commit_with_prepared_blindness2::<E>(
//             &bases_g1,
//             &bases_g2,
//             &prepared_blindness,
//         );

//         //
//         // Sigma Protocol Phase 2 Challenge (We use precomputed challenge, no phase 2 here)
//         //

//         //
//         // Sigma Protocol Phase 3 Responses
//         //

//         // generate witness vector with t the signature randomizer
//         let witnesses = Helpers::add_scalar_to_vector::<E>(&t, &setup.messages);

//         // commit to them in G_T
//         let witness_commitment_gt =
//             Helpers::compute_gt_from_g1_g2_scalars::<E>(&bases_g1, &bases_g2, &witnesses);

//         // generate schnorr responses
//         let responses =
//             SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &witnesses, &challenge);

//         // test schnorr verification
//         let is_valid = SchnorrProtocolPairing::verify(
//             &schnorr_commitment_gt.t_com,
//             &witness_commitment_gt,
//             &challenge,
//             &bases_g1,
//             &bases_g2,
//             &responses.0,
//         );

//         assert!(is_valid, "Schnorr verification failed in prove_equality");

//         let proof = ProofOfKnowledge {
//             randomized_signature: (sigma_prime.sigma1, sigma_prime.sigma2),
//             signature_commitment: signature_commitment_gt,
//             schnorr_commitment: schnorr_commitment_gt.t_com,
//             challenge: *challenge,
//             responses: responses.0,
//         };

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     pub fn verify_batch_equality<E: Pairing>(
//         setups: &[PSTestSetup<E>],
//         serialized_proofs: &[Vec<u8>],
//     ) -> Result<bool, String> {
//         // 1. Validate inputs
//         if setups.len() != serialized_proofs.len() {
//             return Err("Number of setups must match number of proofs".to_string());
//         }
//         if setups.is_empty() {
//             return Err("At least one setup-proof pair required".to_string());
//         }

//         // 2. deserialize proofs
//         let mut all_responses = Vec::with_capacity(serialized_proofs.len());
//         for (idx, (setup, proof_bytes)) in setups.iter().zip(serialized_proofs.iter()).enumerate() {
//             // 2.1 Deserialize proof
//             let proof: ProofOfKnowledge<E> =
//                 CanonicalDeserialize::deserialize_compressed(&proof_bytes[..])
//                     .map_err(|_| format!("Failed to deserialize proof at index {}", idx))?;

//             let computed_signature_commitment = Helpers::compute_gt::<E>(
//                 &[
//                     proof.randomized_signature.1,
//                     proof
//                         .randomized_signature
//                         .0
//                         .into_group()
//                         .neg()
//                         .into_affine(),
//                 ],
//                 &[setup.pk.g2, setup.pk.x_g2],
//             );
//             if computed_signature_commitment != proof.signature_commitment {
//                 return Err(format!(
//                     "Signature commitment verification failed at index {}",
//                     idx
//                 ));
//             }

//             // 2.3 Prepare bases for verification
//             let base_length = setup.messages.len() + 1;
//             let bases_g1 =
//                 Helpers::copy_point_to_length_g1::<E>(proof.randomized_signature.0, &base_length);
//             let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&setup.pk.g2, &setup.pk.y_g2);

//             // 2.4 Verify Schnorr proof
//             let is_valid = SchnorrProtocolPairing::verify(
//                 &proof.schnorr_commitment,
//                 &proof.signature_commitment,
//                 &proof.challenge,
//                 &bases_g1,
//                 &bases_g2,
//                 &proof.responses,
//             );

//             if !is_valid {
//                 return Err(format!(
//                     "Schnorr proof verification failed at index {}",
//                     idx
//                 ));
//             }

//             // Store responses for consistency check
//             let id_response = proof.responses[0];
//             all_responses.push(id_response);
//         }

//         // 3. Verify consistency of first response across all proofs
//         let first_response = all_responses[0];
//         for (idx, response) in all_responses.iter().enumerate().skip(1) {
//             if response != &first_response {
//                 return Err(format!(
//                     "Inconsistent first response at index {}. Expected {:?}, found {:?}",
//                     idx, first_response, response
//                 ));
//             }
//         }

//         Ok(true)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::test_helpers::{create_ps_test_setup, create_ps_with_userid};
//     use ark_bls12_381::{Bls12_381, Fr};
//     use ark_std::rand::{rngs::StdRng, SeedableRng};
//     use ark_std::test_rng;
//     use ark_std::UniformRand;
//     #[test]
//     fn test_prove_and_verify_knowledge() {
//         let setup = create_ps_test_setup::<Bls12_381>(6);
//         let proof = PSProofs::prove_knowledge(&setup);
//         assert!(PSProofs::verify_knowledge(&setup, &proof));
//     }

//     #[test]
//     fn test_selective_disclosure() {
//         // Setup
//         let message_count = 5; // 5 messages + 1 for tt
//         let setup = create_ps_test_setup::<Bls12_381>(message_count);

//         // Choose indices to disclose (e.g., disclose messages at index 1 and 3)
//         let disclosed_indices = vec![1, 3];

//         // Generate the proof
//         let proof = PSProofs::prove_selective_disclosure(&setup, &disclosed_indices)
//             .expect("Proof generation should succeed");

//         // Verify the proof
//         let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
//             .expect("Proof verification should complete");

//         assert!(is_valid, "Selective disclosure proof should be valid");

//         // Test with invalid disclosed indices
//         let invalid_indices = vec![message_count]; // This index is out of bounds
//         let result = PSProofs::prove_selective_disclosure(&setup, &invalid_indices);
//         assert!(
//             result.is_err(),
//             "Proof generation should fail with invalid indices"
//         );

//         // Test disclosing all messages
//         let all_indices: Vec<usize> = (0..message_count).collect();
//         let result = PSProofs::prove_selective_disclosure(&setup, &all_indices);
//         assert!(result.is_ok(), "Should be able to disclose all messages");

//         // // Test disclosing no messages
//         let no_indices: Vec<usize> = vec![];
//         let proof = PSProofs::prove_selective_disclosure(&setup, &no_indices)
//             .expect("Should be able to generate proof with no disclosed messages");
//         let is_valid = PSProofs::verify_selective_disclosure(&setup, &proof)
//             .expect("Should be able to verify proof with no disclosed messages");
//         assert!(is_valid, "Proof with no disclosed messages should be valid");
//     }

//     // #[test]
//     // fn test_equality_proof() {
//     //     // Setup
//     //     let mut rng = test_rng();
//     //     let user_id = Fr::rand(&mut rng);
//     //     let user_id_blindness = Fr::rand(&mut rng);
//     //     let challenge = Fr::rand(&mut rng);
//     //     let message_count = 5;

//     //     let mut setup1 = create_ps_with_userid::<Bls12_381>(message_count, &user_id);
//     //     let mut setup2 = create_ps_with_userid::<Bls12_381>(message_count, &user_id);

//     //     // Generate the proof
//     //     let proof1 = PSProofs::prove_with_userid(&setup1, &user_id_blindness, &challenge)
//     //         .expect("Proof generation should succeed");

//     //     let proof2 = PSProofs::prove_with_userid(&setup2, &user_id_blindness, &challenge)
//     //         .expect("Proof generation should succeed");

//     //     // Prepare inputs for batch verification
//     //     let setups = vec![setup1, setup2];
//     //     let serialized_proofs = vec![proof1, proof2];

//     //     // Perform batch verification
//     //     match PSProofs::verify_batch_equality::<Bls12_381>(&setups, &serialized_proofs) {
//     //         Ok(true) => {
//     //             println!("All proofs verified successfully and share consistent first response")
//     //         }
//     //         Ok(false) => panic!("Unexpected verification failure"),
//     //         Err(e) => panic!("Verification error: {}", e),
//     //     }
//     // }
// }
