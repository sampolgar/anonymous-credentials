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
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
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

// #[derive(CanonicalSerialize, CanonicalDeserialize)]
// pub struct SelectiveDisclosureProof<E: Pairing> {
//     pub randomized_signature: RandomizedSignature<E>,
//     pub schnorr_commitment_1: SchnorrCommitment<G>,
//     pub schnorr_responses_1: Vec<E::ScalarField>,
//     pub schnorr_commitment_2: E::G1Affine,
//     pub schnorr_responses_2: Vec<E::ScalarField>,
//     pub challenge: E::ScalarField,
//     pub disclosed_messages: Vec<(usize, E::ScalarField)>,
// }

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SelectiveDisclosureProof<E: Pairing> {
    pub randomized_signature: RandomizedSignature<E>,
    pub schnorr_commitment_1: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_1: SchnorrResponses<E::G1Affine>,
    pub schnorr_commitment_2: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_2: SchnorrResponses<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub disclosed_messages: Vec<(usize, E::ScalarField)>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct EqualityProof<E: Pairing> {
    pub randomized_signature: RandomizedSignature<E>,
    pub t1_commitment: SchnorrCommitment<E::G1Affine>,
    pub t2_commitment: SchnorrCommitment<E::G1Affine>,
    pub t3_commitment: SchnorrCommitment<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub t1_responses: SchnorrResponses<E::G1Affine>,
    pub t2_responses: SchnorrResponses<E::G1Affine>,
    pub t3_responses: SchnorrResponses<E::G1Affine>,
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
            schnorr_commitment_1,
            schnorr_responses_1,
            schnorr_commitment_2,
            schnorr_responses_2,
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

    pub fn verify_selective_disclosure<E: Pairing>(
        pk: &keygen::PublicKey<E>,
        serialized_proof: &[u8],
        disclosed_messages: &[(usize, E::ScalarField)],
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let proof: SelectiveDisclosureProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 1. Verify the randomized signature
        if !proof.randomized_signature.verify_pairing(pk) {
            return Ok(false);
        }

        // 2. Verify the first Schnorr proof: Ābar/d = A'^-e · h0^r2
        // Verifier reconstructs
        let bases_1 = vec![proof.randomized_signature.a_prime, pk.h0];
        let public_statement_1 = (proof.randomized_signature.a_bar
            + proof.randomized_signature.d.into_group().neg())
        .into_affine();

        let is_proof_1_valid = SchnorrProtocol::verify(
            &bases_1,
            &public_statement_1,
            &proof.schnorr_commitment_1,
            &proof.schnorr_responses_1,
            &proof.challenge,
        );

        if !is_proof_1_valid {
            return Ok(false);
        }

        // 3. Verify the second Schnorr proof: g1 * \prod_{i \in D}h_i^m_i = d^r3 * h_0^{-s'} * \prod_{i \notin D} hi^-mi
        let mut disclosed_product = pk.g1.into_group();
        for &(i, message) in disclosed_messages {
            disclosed_product += pk.h_l[i].mul(message);
        }
        let public_statement_2 = disclosed_product.into_affine();

        let mut bases_2 = vec![
            proof.randomized_signature.d,
            pk.h0.into_group().neg().into_affine(),
        ];
        for i in 0..pk.h_l.len() {
            if !disclosed_messages.iter().any(|&(j, _)| i == j) {
                bases_2.push(pk.h_l[i].into_group().neg().into_affine());
            }
        }

        let is_proof_2_valid = SchnorrProtocol::verify(
            &bases_2,
            &public_statement_2,
            &proof.schnorr_commitment_2,
            &proof.schnorr_responses_2,
            &proof.challenge,
        );

        if !is_proof_2_valid {
            return Ok(false);
        }

        // If all checks pass, the proof is valid
        Ok(true)
    }

    pub fn prove_equality<E: Pairing, R: Rng>(
        signature: &Signature<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        equality_indices: &[(usize, E::ScalarField)],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Validate indices
        if equality_indices.iter().any(|&(i, _)| i >= messages.len()) {
            return Err(ProofError::InvalidEqualityIndex);
        }
        if equality_indices.is_empty() {
            return Err(ProofError::NoEqualityIndices);
        }

        // Randomize the signature
        let randomized_sig = signature.prepare_for_proof(pk, messages, rng);

        // Prepare bases for T1, T2, and T3
        let t1_bases = vec![randomized_sig.a_prime, pk.h0];
        let mut t2_bases = vec![pk.g1, pk.h0.neg()];
        t2_bases.extend(pk.h_l.iter().cloned());
        let t3_bases: Vec<E::G1Affine> = equality_indices.iter().map(|&(i, _)| pk.h_l[i]).collect();

        // Create Schnorr commitments
        let t1_commitment = SchnorrProtocol::commit(&t1_bases, rng);
        let t2_commitment = SchnorrProtocol::commit(&t2_bases, rng);
        let t3_commitment = SchnorrProtocol::commit(&t3_bases, rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(rng);

        // Prepare witnesses
        let t1_witnesses = vec![randomized_sig.e.neg(), randomized_sig.r2];
        let mut t2_witnesses = vec![randomized_sig.r3, randomized_sig.s_prime.neg()];
        t2_witnesses.extend(messages.iter().cloned());
        let t3_witnesses: Vec<E::ScalarField> = equality_indices
            .iter()
            .map(|&(i, m_prime)| messages[i] - m_prime)
            .collect();

        // Create Schnorr proofs
        let t1_responses = SchnorrProtocol::prove(&t1_commitment, &t1_witnesses, &challenge);
        let t2_responses = SchnorrProtocol::prove(&t2_commitment, &t2_witnesses, &challenge);
        let t3_responses = SchnorrProtocol::prove(&t3_commitment, &t3_witnesses, &challenge);

        // Construct the proof
        let proof = EqualityProof {
            randomized_signature: randomized_sig,
            t1_commitment,
            t2_commitment,
            t3_commitment,
            challenge,
            t1_responses,
            t2_responses,
            t3_responses,
            equality_indices: equality_indices.iter().map(|&(i, _)| i).collect(),
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    pub fn verify_equality<E: Pairing>(
        pk: &keygen::PublicKey<E>,
        serialized_proof: &[u8],
        equality_checks: &[(usize, E::ScalarField)],
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let proof: EqualityProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify the randomized signature
        if !proof.randomized_signature.verify_pairing(pk) {
            return Ok(false);
        }

        // Reconstruct bases
        let t1_bases = vec![proof.randomized_signature.a_prime, pk.h0];
        let mut t2_bases = vec![pk.g1, pk.h0.neg()];
        t2_bases.extend(pk.h_l.iter().cloned());
        let t3_bases: Vec<E::G1Affine> =
            proof.equality_indices.iter().map(|&i| pk.h_l[i]).collect();

        // Compute public statements
        let t1_statement = (proof.randomized_signature.a_bar - proof.randomized_signature.d).neg();
        let t2_statement = proof
            .randomized_signature
            .d
            .mul(proof.randomized_signature.r3)
            + pk.h0.mul(proof.randomized_signature.s_prime.neg());
        let t3_statement = E::G1::zero().into_affine();

        // Verify Schnorr proofs
        let t1_valid = SchnorrProtocol::verify(
            &t1_bases,
            &t1_statement,
            &proof.t1_commitment,
            &proof.t1_responses,
            &proof.challenge,
        );

        let t2_valid = SchnorrProtocol::verify(
            &t2_bases,
            &t2_statement,
            &proof.t2_commitment,
            &proof.t2_responses,
            &proof.challenge,
        );

        let t3_valid = SchnorrProtocol::verify(
            &t3_bases,
            &t3_statement,
            &proof.t3_commitment,
            &proof.t3_responses,
            &proof.challenge,
        );

        Ok(t1_valid && t2_valid && t3_valid)
    }
    pub fn prove_equality<E: Pairing, R: Rng>(
        signature: &Signature<E>,
        pk: &keygen::PublicKey<E>,
        messages: &[E::ScalarField],
        equality_indices: &[(usize, E::ScalarField)],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Validate indices
        if equality_indices.iter().any(|&(i, _)| i >= messages.len()) {
            return Err(ProofError::InvalidEqualityIndex);
        }
        if equality_indices.is_empty() {
            return Err(ProofError::NoEqualityIndices);
        }

        // Randomize the signature
        let randomized_sig = signature.prepare_for_proof(pk, messages, rng);

        // Prepare bases and exponents for the equality proof
        let mut bases = vec![randomized_sig.a_prime];
        let mut exponents = vec![randomized_sig.e.neg()];

        for &(i, external_message) in equality_indices {
            bases.push(pk.h_l[i]);
            exponents.push(external_message - messages[i]);
        }

        // Create Schnorr proof
        let challenge = E::ScalarField::rand(rng);
        let schnorr_commitment = SchnorrProtocol::commit(&bases, rng);
        let schnorr_responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Construct the proof
        let proof = EqualityProof {
            randomized_signature: randomized_sig,
            schnorr_commitment: schnorr_commitment.com_t,
            challenge,
            responses: schnorr_responses.0,
            equality_indices: equality_indices.iter().map(|&(i, _)| i).collect(),
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_equality_proof() {
        let mut rng = test_rng();
        let message_count = 5;
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.secret_key();
        let pk = key_pair.public_key();

        // Create messages
        let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..message_count)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // Sign messages
        let signature = Signature::sign(pk, sk, &messages, &mut rng);

        // Create equality proof
        let equality_indices = vec![(1, messages[1]), (3, messages[3])];
        let proof_result =
            BBSPlusProofs::prove_equality(&signature, pk, &messages, &equality_indices, &mut rng);

        assert!(proof_result.is_ok(), "Failed to create equality proof");
        let proof = proof_result.unwrap();

        // Verify equality proof
        let verify_result = BBSPlusProofs::verify_equality(pk, &proof, &equality_indices);
        assert!(verify_result.is_ok(), "Failed to verify equality proof");
        assert!(verify_result.unwrap(), "Equality proof verification failed");

        // Test with incorrect message
        let incorrect_equality_indices = vec![(1, messages[1]), (3, messages[2])];
        let incorrect_verify_result =
            BBSPlusProofs::verify_equality(pk, &proof, &incorrect_equality_indices);
        assert!(
            incorrect_verify_result.is_ok(),
            "Failed to verify incorrect equality proof"
        );
        assert!(
            !incorrect_verify_result.unwrap(),
            "Incorrect equality proof should fail verification"
        );
    }
}
