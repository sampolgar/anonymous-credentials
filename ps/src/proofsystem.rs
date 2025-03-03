use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::{commitment::Commitment, signature::PSSignature};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::Group;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use schnorr::schnorr_pairing::{
    SchnorrCommitmentPairing, SchnorrProtocolPairing, SchnorrResponsesPairing,
};
use thiserror::Error;
// use utils::helpers::Helpers;
use crate::utils::PSUtils;
use utils::pairing::{create_check, verify_pairing_equation, PairingCheck};

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub statement: E::G1Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

pub struct CommitmentProofs;

impl CommitmentProofs {
    /// Generate a proof of knowledge of a commitment in G1
    ///
    /// # Arguments
    /// * `commitment` - The commitment to prove knowledge of
    ///
    /// # Returns
    /// A serialized proof
    pub fn pok_commitment_prove<E: Pairing>(
        commitment: &Commitment<E>,
    ) -> Result<Vec<u8>, ProofError> {
        let mut rng = ark_std::test_rng();

        // Get bases and exponents for the proof
        let bases = commitment.get_bases();
        let exponents = commitment.get_exponents();

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(&mut rng);

        // Generate responses
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create and serialize proof with explicit type annotation
        let proof: CommitmentProof<E> = CommitmentProof {
            statement: commitment.commitment,
            schnorr_commitment,
            bases,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof of knowledge of a commitment in G1
    ///
    /// # Arguments
    /// * `serialized_proof` - The serialized proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn pok_commitment_verify<E: Pairing>(serialized_proof: &[u8]) -> Result<bool, ProofError> {
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &proof.bases,
            &proof.statement,
            &proof.schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        Ok(is_valid)
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SignatureProof<E: Pairing> {
    pub randomized_signature: PSSignature<E>,
    pub schnorr_commitment: PairingOutput<E>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

pub struct SignatureProofs;
impl SignatureProofs {
    ///
    pub fn pok_signature<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &Vec<E::ScalarField>,
        unblind_signature: &PSSignature<E>,
    ) -> Vec<u8> {
        let mut rng = ark_std::test_rng();
        let r = E::ScalarField::rand(&mut rng);
        let t = E::ScalarField::rand(&mut rng);
        let sigma_prime = unblind_signature.rerandomize(&r, &t);
        let challenge = E::ScalarField::rand(&mut rng);

        let exponents = PSUtils::add_scalar_to_end_of_vector::<E>(messages, &t);
        let base_length = pp.n + 1;

        let bases_g1 = PSUtils::copy_point_to_length::<E>(sigma_prime.sigma1, &base_length);
        let bases_g2 = pk.get_bases_g2();

        let schnorr_commitment_pairing =
            SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);
        let schnorr_commitment_gt = schnorr_commitment_pairing.schnorr_commitment;

        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment_pairing, &exponents, &challenge);
        // let sigma_prime2 = sigma_prime.clone();
        // let responses2 = responses.clone();

        let proof = SignatureProof {
            randomized_signature: sigma_prime,
            schnorr_commitment: schnorr_commitment_gt,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof).unwrap();
        serialized_proof
    }

    pub fn verify_knowledge<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> bool {
        let proof: SignatureProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof).unwrap();

        let computed_signature_commitment = PSUtils::compute_gt::<E>(
            &[
                proof.randomized_signature.sigma2,
                proof
                    .randomized_signature
                    .sigma1
                    .into_group()
                    .neg()
                    .into_affine(),
            ],
            &[pp.g2, pk.x_g2],
        );

        // 2. Prepare bases for verification
        let base_length = pp.n + 1;
        let bases_g1 =
            PSUtils::copy_point_to_length::<E>(proof.randomized_signature.sigma1, &base_length);
        let mut bases_g2 = pk.y_g2.clone(); // [Y_{21}, ..., Y_{2n}]
        bases_g2.push(pp.g2); // Append g2 for t

        // 3. Verify the Schnorr proof
        let is_valid = SchnorrProtocolPairing::verify(
            &computed_signature_commitment,
            &proof.schnorr_commitment,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use ark_bls12_381::{Bls12_381, Fr};
    #[test]
    fn test_signature_proof_system() {
        // Initialize test environment
        let n = 4; // Support 4 messages
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create random messages and blinding factor
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let t = Fr::rand(&mut rng);

        // Create commitment
        let commitment = Commitment::new(&pp, &pk, &messages, &t);

        // Create signature on the commitment
        let blind_signature =
            PSSignature::blind_sign(&pp, &pk, &sk, &commitment.commitment, &mut rng);

        // Unblind the signature
        let unblind_signature = blind_signature.unblind(&t);

        // Verify the signature (optional, just for sanity check)
        let is_signature_valid = unblind_signature.public_verify(&pp, &messages, &pk);
        assert!(is_signature_valid, "Signature verification failed");

        // Generate proof of knowledge of the signature
        let proof =
            SignatureProofs::pok_signature(&pp.clone(), &pk.clone(), &messages, &unblind_signature);

        // Verify the proof
        let is_proof_valid = SignatureProofs::verify_knowledge(&pp, &pk, &proof);

        assert!(is_proof_valid, "Signature proof verification failed");
    }

    #[test]
    fn test_commitment_proof_system_integration() {
        // Initialize test environment
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create random messages and blinding factor
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let t = Fr::rand(&mut rng);

        // Create commitment
        let commitment = Commitment::new(&pp, &pk, &messages, &t);

        // Generate proof of knowledge
        let proof = commitment
            .prove_opening()
            .expect("Proof generation should succeed");

        // Verify the proof
        let is_valid = CommitmentProofs::pok_commitment_verify::<Bls12_381>(&proof)
            .expect("Proof verification should complete");

        assert!(is_valid, "Commitment proof verification should succeed");
    }
}
