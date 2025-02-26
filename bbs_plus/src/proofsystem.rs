use crate::keygen::{self, PublicKey};
use crate::publicparams::PublicParams;
use crate::signature::{BBSPlusRandomizedSignature, BBSPlusSignature};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_groth16::Proof;
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
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Placeholder error: {0}")]
    PlaceholderError(String),
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ProofOfKnowledge<E: Pairing> {
    pub randomized_sig: BBSPlusRandomizedSignature<E>,
    pub schnorr_commitment_1: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_1: SchnorrResponses<E::G1Affine>,
    pub schnorr_commitment_2: SchnorrCommitment<E::G1Affine>,
    pub schnorr_responses_2: SchnorrResponses<E::G1Affine>,
    pub challenge: E::ScalarField,
}

pub struct ProofSystem;

impl ProofSystem {
    // Proves Knowledge of a BBS+ Signature
    pub fn prove<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        randomized_sig: &BBSPlusRandomizedSignature<E>,
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

        // this can be deleted, this is a test to see if it works before creating prover/verifier
        let proof_1_test = SchnorrProtocol::verify(
            &bases_1,
            &public_statement_1,
            &schnorr_commitment_1,
            &schnorr_responses_1,
            &challenge,
        );

        assert!(proof_1_test, "proof 1 test isn't valid!");

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
        // Verify the second proof (this can be removed in production)
        let proof_2_valid = SchnorrProtocol::verify(
            &bases_2,
            &public_statement_2,
            &schnorr_commitment_2,
            &schnorr_responses_2,
            &challenge,
        );
        assert!(proof_2_valid, "Proof 2 is not valid!");

        let proof = ProofOfKnowledge {
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
    pub fn verify_proof<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let proof: ProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 1. Verify the randomized signature for sanity
        if !proof.randomized_sig.verify_pairing(&pp, &pk) {
            return Ok(false);
        }

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

        let proof = ProofSystem::prove(
            &setup.pp,
            &randomized_signature,
            &setup.pk,
            &setup.messages,
            &mut rng,
        );

        assert!(
            proof.is_ok(),
            "Expected the prove function to succeed, but it failed"
        );
        // If the prove function succeeds, verify the proof
        if let Ok(serialized_proof) = proof {
            let verification_result =
                ProofSystem::verify_proof(&setup.pp, &setup.pk, &serialized_proof);

            assert!(
                verification_result.unwrap_or(false),
                "Proof verification failed"
            );
        }
    }
}
