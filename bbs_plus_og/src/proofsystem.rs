use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusOgSignature;
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

/// Full proof of knowledge of a BBS+ signature
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct BBSPlusProofOfKnowledge<E: Pairing> {
    pub statement1: E::G1Affine,
    pub statement2: E::G1Affine,
    pub statement3: PairingOutput<E>,
    pub schnorr_commitment1: E::G1Affine,
    pub schnorr_commitment2: E::G1Affine,
    pub schnorr_commitment3: PairingOutput<E>,
    pub schnorr_responses1: Vec<E::ScalarField>,
    pub schnorr_responses2: Vec<E::ScalarField>,
    pub schnorr_responses3: Vec<E::ScalarField>,
    pub bases1: Vec<E::G1Affine>,
    pub pairing_bases_g1: Vec<E::G1Affine>,
    pub pairing_bases_g2: Vec<E::G2Affine>,
    pub challenge: E::ScalarField,
}
/// Proof of knowledge of a commitment
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: E::G1Affine,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

/// Pedersen commitment with proof of knowledge
// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
// pub struct CommitmentWithProof<E: Pairing> {
//     pub commitment: E::G1Affine,
//     pub proof: Vec<u8>,
// }

pub struct ProofSystem;

impl ProofSystem {
    pub fn pok_signature_prove<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusOgSignature<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Validate basic inputs
        assert_eq!(messages.len(), pp.L, "Invalid number of messages");
        let rand_sig = signature.randomize(&pp, &pk, &messages, rng);
        let challenge = E::ScalarField::rand(rng);
        let (g1, g2) = pp.get_g1_g2();

        // PoK A1 = g1^r1 g2^r2
        // schnorr_commitment1 = g1^rho_r1 * g2^rho_r2
        let statement1 = rand_sig.A1;
        let rho_r1 = E::ScalarField::rand(rng);
        let rho_r2 = E::ScalarField::rand(rng);
        let bases1: Vec<<E as Pairing>::G1Affine> = vec![g1, g2];
        let exponents1 = vec![rand_sig.r1, rand_sig.r2];
        let blinding_factors1 = vec![rho_r1, rho_r2];
        let schnorr_commitment1 =
            SchnorrProtocol::commit_with_prepared_blindings(&bases1, &blinding_factors1);
        let schnorr_responses1 =
            SchnorrProtocol::prove(&schnorr_commitment1, &exponents1, &challenge);

        // PoK A1^e = g1^delta1 g2^delta2
        // schnorr commitment2 = g1^rho3, g2^rho4
        let rho_delta1 = E::ScalarField::rand(rng);
        let rho_delta2 = E::ScalarField::rand(rng);
        let blinding_factors2 = vec![rho_delta1, rho_delta2];
        let statement2 = rand_sig.A1.mul(signature.e).into_affine();
        // let bases2 = bases1;
        let exponents2 = vec![rand_sig.delta1, rand_sig.delta2];
        let schnorr_commitment2 =
            SchnorrProtocol::commit_with_prepared_blindings(&bases1, &blinding_factors2);
        let schnorr_responses2 =
            SchnorrProtocol::prove(&schnorr_commitment2, &exponents2, &challenge);

        // PoK pairing result e(A2, h0)^-e . e(g2,w)^r1 . e(g1, h0)^s . e(g2, h0)^m1....e(gL+1,h0)^m_L
        let rho_neg_e = E::ScalarField::rand(rng);
        let rho_s = E::ScalarField::rand(rng);
        let rho_messages: Vec<E::ScalarField> = (0..messages.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        let statement3 = rand_sig.pairing_statement;

        // [rho_neg_e, rho_r1, rho_delta1, rho_s, rho_m1,...,mL]
        let mut blinding_factors3 = vec![rho_neg_e, rho_r1, rho_delta1, rho_s];
        blinding_factors3.extend(&rho_messages);

        // Compute T3 (pairing commitment)
        let schnorr_commitment3 = SchnorrProtocolPairing::commit_with_prepared_blindness::<E>(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &blinding_factors3,
        );

        // pairing exponents: [-e, r1, delta1, s, m1,...,mL]
        // prepared randomness vec![rho_neg_e, rho_r1, rho_delta1, rho_s, rho_m1,...,rho_mL]
        let schnorr_responses3 = SchnorrProtocolPairing::prove(
            &schnorr_commitment3,        //this has the blinding factors associated to it
            &rand_sig.pairing_exponents, //this is the exponents
            &challenge,
        );

        let proof = BBSPlusProofOfKnowledge {
            statement1,
            statement2,
            statement3,
            schnorr_commitment1: schnorr_commitment1.commited_blindings,
            schnorr_commitment2: schnorr_commitment2.commited_blindings,
            schnorr_commitment3: schnorr_commitment3.schnorr_commitment,
            schnorr_responses1: schnorr_responses1.0,
            schnorr_responses2: schnorr_responses2.0,
            schnorr_responses3: schnorr_responses3.0,
            bases1: bases1.clone(),
            pairing_bases_g1: rand_sig.pairing_bases_g1.clone(),
            pairing_bases_g2: rand_sig.pairing_bases_g2.clone(),
            challenge,
        };

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    /// Verify a proof of knowledge of a BBS+ signature
    /// This is a simplified version, the proof includes ALL GT points precomputed. In real life, the verifier would receive A2
    /// and compute the pairing statement e(A2, w) / e(g0,h0) and e(A2, h0)
    /// The other base points can be precomputed and available as public parameters
    pub fn pok_signature_verify<E: Pairing>(
        pp: &PublicParams<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // 1. Deserialize the proof
        let proof: BBSPlusProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 2. Verify Schnorr proof 1
        let is_schnorr1_valid = SchnorrProtocol::verify_schnorr(
            &proof.bases1,
            &proof.statement1,
            &proof.schnorr_commitment1,
            &proof.schnorr_responses1,
            &proof.challenge,
        );

        if !is_schnorr1_valid {
            println!("Schnorr proof 1 verification failed");
            return Ok(false);
        }
        println!("Schnorr proof 1 is valid");

        let is_schnorr2_valid = SchnorrProtocol::verify_schnorr(
            &proof.bases1,
            &proof.statement2,
            &proof.schnorr_commitment2,
            &proof.schnorr_responses2,
            &proof.challenge,
        );

        if !is_schnorr2_valid {
            println!("Schnorr proof 2 verification failed");
            return Ok(false);
        }
        println!("Schnorr proof 2 is valid");

        let is_schnorr3_valid = SchnorrProtocolPairing::verify(
            &proof.statement3,
            &proof.schnorr_commitment3,
            &proof.challenge,
            &proof.pairing_bases_g1,
            &proof.pairing_bases_g2,
            &proof.schnorr_responses3,
        );

        if !is_schnorr3_valid {
            println!("Schnorr proof 3 verification failed");
            return Ok(false);
        }
        println!("Schnorr proof 3 is valid");

        //  responses1[0] = responses3[1]
        // responses2[0] = responses3[2]
        let equal_responses = proof.schnorr_responses1[0] == proof.schnorr_responses3[1]
            && proof.schnorr_responses2[0] == proof.schnorr_responses3[2];

        if !equal_responses {
            println!("Responses aren't equal between proofs");
            return Ok(false);
        }
        println!("Responses are equal, all proofs hold");

        Ok(true)
    }

    /// Create a commitment and proof of knowledge
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `messages` - Array of messages to commit to
    /// * `s` - Blinding factor
    /// * `rng` - Random number generator
    ///
    /// # Returns
    /// * Commitment with proof
    pub fn create_commitment_proof<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        s_prime: &E::ScalarField,
        rng: &mut R,
    ) -> Result<Vec<u8>, ProofError> {
        // Validate inputs
        assert_eq!(messages.len(), pp.L, "Invalid number of messages");

        // Calculate the commitment: C = h0^s * h1^m1 * ... * hL^mL
        let mut bases = pp.g2_to_L.clone();
        bases.insert(0, pp.g1);

        let mut exponents = messages.to_vec();
        exponents.insert(0, *s_prime);

        let commitment = E::G1::msm_unchecked(&bases, &exponents).into_affine();

        // Generate Schnorr proof for the commitment
        let schnorr_commitment = SchnorrProtocol::commit(&bases, rng);
        let challenge = E::ScalarField::rand(rng);
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &exponents, &challenge);

        // Create the proof struct
        let proof = CommitmentProof::<E> {
            commitment,
            schnorr_commitment: schnorr_commitment.commited_blindings,
            bases: bases.clone(),
            challenge,
            responses: responses.0,
        };

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;
        Ok(serialized_proof)
    }

    /// Verify a commitment proof
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `commitment_proof` - Commitment with proof
    ///
    /// # Returns
    /// * Result indicating whether the proof is valid
    pub fn verify_commitment_proof<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // Deserialize the proof
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify the Schnorr proof
        let is_valid = SchnorrProtocol::verify_schnorr(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &proof.responses,
            &proof.challenge,
        );

        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use crate::signature::BBSPlusOgSignature;
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
        let signature = BBSPlusOgSignature::sign(&pp, &sk, &messages, &mut rng);

        // Verify the signature directly
        let is_valid = signature.verify(&pp, &pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Generate a proof of knowledge
        let proof = ProofSystem::pok_signature_prove(&pp, &pk, &signature, &messages, &mut rng)
            .expect("Failed to generate proof");

        // Verify the proof
        let is_proof_valid =
            ProofSystem::pok_signature_verify(&pp, &proof).expect("Failed to verify proof");

        assert!(is_proof_valid, "Proof verification failed");
    }

    #[test]
    fn test_commitment_proof() {
        // Initialize test environment
        let mut rng = test_rng();
        let L = 2; // Support 2 messages

        // Generate public parameters
        let pp = PublicParams::<Bls12_381>::new(&L, &mut rng);

        // Generate a keypair
        let (_, pk) = gen_keys(&pp, &mut rng);

        // Create random messages and blinding factor
        let messages: Vec<Fr> = (0..L).map(|_| Fr::rand(&mut rng)).collect();
        let s = Fr::rand(&mut rng);

        // Create commitment and proof
        let proof = ProofSystem::create_commitment_proof(&pp, &pk, &messages, &s, &mut rng)
            .expect("Failed to create commitment proof");

        // Verify the proof
        let is_valid = ProofSystem::verify_commitment_proof(&pp, &pk, &proof)
            .expect("Verification process failed");

        assert!(is_valid, "Commitment proof verification failed");
    }
}
