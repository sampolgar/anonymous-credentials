// use crate::commitment::{
//     Commitment, CommitmentError, CommitmentProof, SymmetricCommitment, SymmetricCommitmentKey,
// };
// use ark_ec::pairing::Pairing;
// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use ark_std::{rand::Rng, vec::Vec, UniformRand};
// use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

// pub struct CommitmentProofs;

// impl CommitmentProofs {
//     /// Create a proof of knowledge for a Commitment
//     pub fn pok_commitment_prove<E: Pairing>(
//         commitment: &Commitment<E>,
//         rng: &mut impl Rng,
//     ) -> Result<Vec<u8>, CommitmentError> {
//         let schnorr_commitment = SchnorrProtocol::commit(&commitment.bases, rng);
//         let challenge = E::ScalarField::rand(rng);
//         let responses =
//             SchnorrProtocol::prove(&schnorr_commitment, &commitment.exponents, &challenge);

//         let proof: CommitmentProof<E> = CommitmentProof {
//             bases: commitment.bases.clone(),
//             commitment: commitment.cm,
//             schnorr_commitment,
//             challenge,
//             responses: responses.0,
//         };

//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     /// Verify a proof of knowledge for a commitment
//     pub fn pok_commitment_verify<E: Pairing>(
//         serialized_proof: &[u8],
//     ) -> Result<bool, CommitmentError> {
//         let proof: CommitmentProof<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

//         // Verify using Schnorr protocol
//         let is_valid = SchnorrProtocol::verify(
//             &proof.bases,
//             &proof.commitment,
//             &proof.schnorr_commitment,
//             &SchnorrResponses(proof.responses.clone()),
//             &proof.challenge,
//         );

//         Ok(is_valid)
//     }
// }
