use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::{commitment::Commitment, signature::PSSignature};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
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
use utils::helpers::Helpers;
use utils::pairing::{create_check, verify_pairing_equation, PairingCheck};

/// Possible errors that can occur during commitment proof operations
#[derive(Error, Debug)]
pub enum ProofError {
    /// The commitment is invalid
    #[error("Invalid commitment")]
    InvalidCommitment,
    /// The proof is invalid
    #[error("Invalid proof")]
    InvalidProof,
    /// The provided index for an equality proof is invalid
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,
    /// Commitments in a batch have different lengths
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,
    /// An error occurred during serialization or deserialization
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Proof of knowledge of a commitment in the G1 group
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
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
            commitment: commitment.commitment,
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
            &proof.commitment,
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
    pub signature_commitment: PairingOutput<E>,
    pub schnorr_commitment: PairingOutput<E>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

pub struct SignatureProofs;
impl SignatureProofs {
    // pub fn pok_signature<E: Pairing>(
    //     pp: PublicParams<E>,
    //     pk: PublicKey<E>,
    //     commitment: &Commitment<E>,
    //     signature: &PSSignature<E>,
    // ) -> Vec<u8> {
    //     let mut rng = ark_std::test_rng();
    //     let r = E::ScalarField::rand(&mut rng);
    //     let t = E::ScalarField::rand(&mut rng);
    //     let sigma_prime = signature.rerandomize(&r, &t);
    //     let base_length = pp.n + 1;

    //     // pairing equation from short randomizable signatures
    //     // e(σ'₁, X̃) · ∏ e(σ'₁, Ỹⱼ)^mⱼ · e(σ'₁, g̃)^t = e(σ'₂, g̃)

    //     // we change to
    //     // ∏ e(σ'₁, Ỹⱼ)^mⱼ · e(σ'₁, g̃)^t = e(σ'₂, g̃) / e(σ'₁, X̃)

    //     // RHS is derived from the randomized signature
    //     // // e(\sigma2', g) . e(\sigma1', X) where one of these will be inversed

    //     // ∏ e(σ'₁, Ỹⱼ)^mⱼ · e(σ'₁, g̃)^t = e(σ'₂, g̃) / e(σ'₁, X̃)
    //     let sigma1_neg = sigma_prime.sigma1.into_group().neg().into_affine();
    //     let rhs_check = create_check::<E>(
    //         &[
    //             (&sigma_prime.sigma2, &pp.g2), // e(σ'₂, g̃)
    //             (&sigma1_neg, &pk.x_g2),       // e(-σ'₁, X̃) which equals (e(σ'₁, X̃))^(-1)
    //         ],
    //         None,
    //     );

    //     // make a vector of scaled sigma1' prime points with exponents
    //     // getexponents = m1,...,mL,t
    //     // get the g2 bases
    //     // make the lhs pairs
    //     let exponents = commitment.get_exponents();
    //     let bases_g2 = commitment.get_bases_g2();
    //     let scaled_sigma1_vec: Vec<E::G1Affine> = exponents
    //         .iter()
    //         .map(|exp| sigma_prime.sigma1.mul(*exp).into_affine())
    //         .collect();

    //     let lhs_pairs: Vec<(&E::G1Affine, &E::G2Affine)> = scaled_sigma1_vec
    //         .iter()
    //         .enumerate()
    //         .map(|(i, scaled)| (scaled, &bases_g2[i]))
    //         .collect();

    //     let lhs_check = create_check(&lhs_pairs, None);

    //     let mut full_check = PairingCheck::<E>::new();
    //     full_check.merge(&lhs_check);
    //     full_check.merge(&rhs_check);
    //     let is_valid = full_check.verify();
    //     println!("Combined verification result: {}", is_valid);

    //     let signature_commitment_gt = sigma_prime.generate_commitment_gt(&pp, &commitment.pk);

    //     // tt, m1, ... ,mn -> does this create bases for m,...,m_l,t or the other way aroudn?
    //     // We need to create e(\sigma1', .) . e(\sigma1', .), ...,
    //     let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &base_length);
    //     // We need to create e(..Y_1) . e(.,Y_2)  .. e(.,g_2)
    //     let bases_g2 = commitment.get_bases_g2();

    //     let schnorr_commitment =
    //         SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);

    //     let challenge = E::ScalarField::rand(&mut rng);

    //     // generate message vector
    //     let exponents = commitment.get_exponents();
    //     let responses = SchnorrProtocolPairing::prove(&schnorr_commitment, &exponents, &challenge);

    //     let responses2 = responses.clone();

    //     let proof = SignatureProof {
    //         randomized_signature: sigma_prime,
    //         // signature_commitment: signature_commitment_gt,
    //         schnorr_commitment_gt: schnorr_commitment.commited_blindings_gt,
    //         challenge,
    //         responses: responses.0,
    //     };

    //     let isvalid = SchnorrProtocolPairing::verify(
    //         &signature_commitment_gt,
    //         &schnorr_commitment.commited_blindings_gt,
    //         &challenge,
    //         &bases_g1,
    //         &bases_g2,
    //         &responses2.0,
    //     );
    //     assert!(isvalid, "pairing not valid");

    //     let mut serialized_proof = Vec::new();
    //     proof.serialize_compressed(&mut serialized_proof).unwrap();
    //     serialized_proof
    // }

    pub fn pok_signature<E: Pairing>(
        pp: PublicParams<E>,
        pk: PublicKey<E>,
        commitment: &Commitment<E>,
        signature: &PSSignature<E>,
    ) -> Vec<u8> {
        let mut rng = ark_std::test_rng();
        let r = E::ScalarField::rand(&mut rng);
        let t = E::ScalarField::rand(&mut rng);
        let sigma_prime = signature.rerandomize(&r, &t);
        let message_length = pp.n + 1;

        // // Generate a commitment to the signature
        let signature_commitment_gt = sigma_prime.generate_commitment_gt(&pp, &pk);

        let exponents = commitment.get_exponents();
        let bases_g1 = Helpers::copy_point_to_length_g1::<E>(sigma_prime.sigma1, &message_length);

        let bases_g2 = commitment.get_bases_g2();
        // let mut bases_g2 = pk.y_g2.clone(); // [Y_{21}, ..., Y_{2n}]
        // bases_g2.push(pp.g2); // Append g2 for t
        assert_eq!(bases_g1.len(), bases_g2.len(), "bases aren't same size");

        let schnorr_commitment_gt =
            SchnorrProtocolPairing::commit::<E, _>(&bases_g1, &bases_g2, &mut rng);

        let challenge = E::ScalarField::rand(&mut rng);

        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &exponents, &challenge);

        let proof = SignatureProof {
            randomized_signature: sigma_prime,
            signature_commitment: signature_commitment_gt,
            schnorr_commitment: schnorr_commitment_gt.commited_blindings_gt,
            challenge,
            responses: responses.0,
        };

        let computed_signature_commitment = Helpers::compute_gt::<E>(
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

        assert_eq!(
            computed_signature_commitment, proof.signature_commitment,
            "must be equal"
        );

        let is_valid = SchnorrProtocolPairing::verify(
            &proof.signature_commitment,
            &proof.schnorr_commitment,
            &proof.challenge,
            &bases_g1,
            &bases_g2,
            &proof.responses,
        );

        assert_eq!(
            proof.responses.len(),
            message_length,
            "responses and base length don't match"
        );

        assert!(is_valid, "signature pok in pok not valid");
        println!("signature pok in  pok valid valid valid");

        // let computed_signature_commitment = Helpers::compute_gt::<E>(
        //     &[
        //         proof.randomized_signature.sigma2,
        //         proof
        //             .randomized_signature
        //             .sigma1
        //             .into_group()
        //             .neg()
        //             .into_affine(),
        //     ],
        //     &[pp.g2, pk.x_g2],
        // );

        // assert_eq!(
        //     computed_signature_commitment, signature_commitment_gt,
        //     "must be equal"
        // );
        // print!("signature commitments are equal");

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

        let computed_signature_commitment = Helpers::compute_gt::<E>(
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
        // assert_eq!(
        //     computed_signature_commitment, proof.signature_commitment,
        //     "must be equal"
        // );

        // 2. Prepare bases for verification
        let base_length = pp.n + 1;
        let bases_g1 =
            Helpers::copy_point_to_length_g1::<E>(proof.randomized_signature.sigma1, &base_length);
        let mut bases_g22 = pk.y_g2.clone(); // [Y_{21}, ..., Y_{2n}]
        bases_g22.push(pp.g2); // Append g2 for t

        let bases_g2 = Helpers::add_affine_to_vector::<E::G2>(&pp.g2, &pk.y_g2);

        // 3. Verify the Schnorr proof
        let is_valid = SchnorrProtocolPairing::verify(
            &computed_signature_commitment,
            &proof.schnorr_commitment,
            &proof.challenge,
            &bases_g1,
            &bases_g22,
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
        let signature = blind_signature.unblind(&t);

        // Verify the signature (optional, just for sanity check)
        let is_signature_valid = signature.public_verify(&pp, &messages, &pk);
        assert!(is_signature_valid, "Signature verification failed");

        // Generate proof of knowledge of the signature
        let proof = SignatureProofs::pok_signature(pp.clone(), pk.clone(), &commitment, &signature);

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

        // Manual verification of the Schnorr proof components
        let proof_obj: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&proof[..])
                .expect("Proof deserialization failed");

        // Verify the bases and commitment in the proof
        assert_eq!(
            proof_obj.commitment, commitment.commitment,
            "Proof commitment should match original"
        );
        assert_eq!(
            proof_obj.bases.len(),
            n + 1,
            "Proof should have correct number of bases"
        );

        // Verify the Schnorr validation equation manually
        let schnorr_valid = SchnorrProtocol::verify(
            &proof_obj.bases,
            &proof_obj.commitment,
            &proof_obj.schnorr_commitment,
            &SchnorrResponses(proof_obj.responses.clone()),
            &proof_obj.challenge,
        );

        assert!(
            schnorr_valid,
            "Manual verification of Schnorr proof should succeed"
        );
    }
}
