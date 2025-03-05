use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlus16RandomizedSignature;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
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

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSPlusProofOfKnowledge<E: Pairing> {
    pub randomized_sig: BBSPlus16RandomizedSignature<E>,
    pub schnorr_commitment_1: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_1: SchnorrResponses<E::G1Affine>,
    pub schnorr_commitment_2: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_2: SchnorrResponses<E::G1Affine>,
    pub challenge: E::ScalarField,
}
/// Pedersen commitment with proof of knowledge
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentWithProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub proof: Vec<u8>,
}

pub struct ProofSystem;

impl ProofSystem {
    // Proves Knowledge of a BBS+ Signature
    pub fn bbs_plus_16_prove<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        randomized_sig: &BBSPlus16RandomizedSignature<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // 1. Prove knowledge of -e, r2 such that Ābar/d = A'^-e · h0^r2
        let bases_1 = vec![randomized_sig.A_prime, pk.h0];
        let exponents_1 = vec![randomized_sig.e.neg(), randomized_sig.r2];
        let public_statement_1 = (randomized_sig
            .A_bar
            .add(randomized_sig.d.into_group().neg()))
        .into_affine();
        let challenge = E::ScalarField::rand(rng);

        let schnorr_commitment_1 = SchnorrProtocol::commit(&bases_1, rng);
        let schnorr_responses_1 =
            SchnorrProtocol::prove(&schnorr_commitment_1, &exponents_1, &challenge);
        // assert!(proof_1_test, "proof 1 test isn't valid!");

        let public_statement_2 = pp.g1;

        // 2. Prove g1 = d^r3 * h_0^{-s'} * \prod_{i}^L hi^-mi
        // 2.1 create exponents vector [r3, -s', -m_i, ..., -m_L]
        let s_prime_neg = -randomized_sig.s_prime;
        let messages_neg: Vec<E::ScalarField> = messages.iter().map(|m| -*m).collect();
        let mut exponents_2 = vec![randomized_sig.r3, s_prime_neg];
        exponents_2.extend(messages_neg);

        // 2.2 create bases vector [d, h_0, h_i, ...., h_L]
        let mut bases_2 = vec![randomized_sig.d, pk.h0];
        bases_2.extend(pk.h1hL.iter().cloned());

        let schnorr_commitment_2 = SchnorrProtocol::commit(&bases_2, rng);
        let schnorr_responses_2 =
            SchnorrProtocol::prove(&schnorr_commitment_2, &exponents_2, &challenge);

        let proof = BBSPlusProofOfKnowledge {
            randomized_sig: randomized_sig.clone(),
            schnorr_commitment_1,
            schnorr_responses_1,
            schnorr_commitment_2,
            schnorr_responses_2,
            challenge,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;
        Ok(serialized_proof)
    }

    // Verifies knowledge of a BBS+ Signature Proof
    pub fn bbs_plus_16_verify_proof<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let proof: BBSPlusProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 2. Verify the first Schnorr proof: Ābar/d = A'^-e · h0^r2
        // Verifier reconstructs
        let bases_1 = vec![proof.randomized_sig.A_prime, pk.h0];
        let public_statement_1 =
            (proof.randomized_sig.A_bar + proof.randomized_sig.d.into_group().neg()).into_affine();

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

        // 3. Verify the second Schnorr proof: g1= d^r3 * h_0^{-s'} * \prod_{i}^L hi^-mi
        let public_statement_2 = pp.g1;

        let mut bases_2 = vec![proof.randomized_sig.d, pk.h0];
        bases_2.extend(pk.h1hL.iter().cloned());

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

        Ok(true)
    }

    // pub fn commitment_prove<E: Pairing, R: Rng>()
    // pub fn commitment_verify
    /// Creates a Pedersen commitment to messages and a proof of knowledge
    pub fn create_commitment_proof<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        s_prime: &E::ScalarField,
        rng: &mut R,
    ) -> Result<CommitmentWithProof<E>, ProofError> {
        assert_eq!(messages.len(), pk.h1hL.len(), "Invalid number of messages");
        // Create Pedersen commitment: Cm = h_0^sprime h_1^m1 ... hL^mL
        let mut exponents = vec![*s_prime];
        exponents.extend(messages.iter().cloned());

        let bases = pk.get_all_h();

        // cm = h_0^s' h_1^m_1 ... h_L^m_L
        let commitment: E::G1 = E::G1::msm(&bases, &exponents).unwrap();
        let challenge = E::ScalarField::rand(rng);
        let schnorr_commitment = SchnorrProtocol::commit(&bases, rng);
        let schnorr_responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &commitment.into_affine(),
            &schnorr_commitment,
            &schnorr_responses,
            &challenge,
        );
        assert!(is_valid, "Generated proof is not valid!");

        // Create proof structure
        let proof = (schnorr_commitment, schnorr_responses, challenge);
        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(CommitmentWithProof {
            commitment: commitment.into_affine(),
            proof: serialized_proof,
        })
    }

    /// Verifies a Pedersen commitment proof
    pub fn verify_commitment_proof<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        commitment_proof: &CommitmentWithProof<E>,
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let (schnorr_commitment, schnorr_responses, challenge): (
            SchnorrCommitment<E::G1Affine>,
            SchnorrResponses<E::G1Affine>,
            E::ScalarField,
        ) = CanonicalDeserialize::deserialize_compressed(&commitment_proof.proof[..])?;

        // Setup for verification
        let bases = pk.get_all_h();

        // Verify the proof
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &commitment_proof.commitment,
            &schnorr_commitment,
            &schnorr_responses,
            &challenge,
        );

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestSetup;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_prove() {
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 4);

        let is_valid = setup
            .signature
            .verify(&setup.pp, &setup.pk, &setup.messages);
        assert!(is_valid, "Signature verification failed");

        let randomized_signature =
            setup
                .signature
                .rerandomize(&setup.pp, &setup.pk, &setup.messages, &mut rng);
        assert!(
            randomized_signature.verify_pairing(&setup.pp, &setup.pk),
            "Randomized signature verification failed"
        );
        let proof = ProofSystem::bbs_plus_16_prove(
            &setup.pp,
            &randomized_signature,
            &setup.pk,
            &setup.messages,
            &mut rng,
        )
        .expect("Failed to generate proof");

        // Verify the proof
        let verification_result =
            ProofSystem::bbs_plus_16_verify_proof(&setup.pp, &setup.pk, &proof)
                .expect("Failed to verify proof");

        assert!(verification_result, "Proof verification failed");
    }

    #[test]
    fn test_commitment_proof_simple() {
        // Create test setup
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 3);

        // Generate random s_prime
        let s_prime = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);

        // Create commitment and proof
        let commitment_proof = ProofSystem::create_commitment_proof(
            &setup.pp,
            &setup.pk,
            &setup.messages,
            &s_prime,
            &mut rng,
        )
        .expect("Failed to create commitment proof");

        // Verify the proof
        let is_valid =
            ProofSystem::verify_commitment_proof(&setup.pp, &setup.pk, &commitment_proof)
                .expect("Failed to verify commitment proof");

        // Assert that verification succeeds
        assert!(is_valid, "Commitment proof verification failed");
    }
}
