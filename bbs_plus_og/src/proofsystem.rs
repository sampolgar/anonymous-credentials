use crate::keygen::PublicKey;
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusSignature;
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

// /// Randomized signature elements for BBS+ proof
// #[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
// pub struct BBSPlusSignatureProofCommitment<E: Pairing> {
//     pub A1: E::G1Affine, // g₁ʳ¹g₂ʳ²
//     pub A2: E::G1Affine, // Ag₁ʳ¹
// }

/// Full proof of knowledge of a BBS+ signature
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct BBSPlusProofOfKnowledge<E: Pairing> {
    pub bases1: Vec<E::G1Affine>,
    pub statement1: E::G1Affine,
    pub schnorr_commitment1: E::G1Affine,
    pub schnorr_responses1: Vec<E::ScalarField>,
    pub statement2: E::G1Affine,
    pub schnorr_commitment2: E::G1Affine,
    pub schnorr_responses2: Vec<E::ScalarField>,
    pub schnorr_commitment3: PairingOutput<E>,
    pub pairing_bases_g1: Vec<E::G1Affine>,
    pub pairing_bases_g2: Vec<E::G2Affine>,
    pub responses3: Vec<E::ScalarField>,
    pub challenge: E::ScalarField,
}

pub struct ProofSystem;

impl ProofSystem {
    pub fn prove_wofancy2<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusSignature<E>,
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
            SchnorrProtocol::commit_with_prepred_blindness(&bases1, &blinding_factors1);
        let schnorr_responses1 =
            SchnorrProtocol::prove(&schnorr_commitment1, &exponents1, &challenge);

        assert!(
            SchnorrProtocol::verify(
                &bases1,
                &statement1,
                &schnorr_commitment1,
                &schnorr_responses1,
                &challenge
            ),
            "schnorr 1 isn't valid"
        );
        println!("schnorr 1 is valid");

        // // schnorr commitment2 = g1^rho3, g2^rho4
        let rho_delta1 = E::ScalarField::rand(rng);
        let rho_delta2 = E::ScalarField::rand(rng);
        let blinding_factors2 = vec![rho_delta1, rho_delta2];
        let statement2 = rand_sig.A1.mul(signature.e).into_affine();
        // let bases2 = bases1;
        let exponents2 = vec![rand_sig.delta1, rand_sig.delta2];
        let schnorr_commitment2 =
            SchnorrProtocol::commit_with_prepred_blindness(&bases1, &blinding_factors2);
        let schnorr_responses2 =
            SchnorrProtocol::prove(&schnorr_commitment2, &exponents2, &challenge);
        assert!(
            SchnorrProtocol::verify(
                &bases1,
                &statement2,
                &schnorr_commitment2,
                &schnorr_responses2,
                &challenge
            ),
            "schnorr 2 isn't valid"
        );
        println!("schnorr 2 is valid");

        // Step 3: Generate blinding factors for the commitments
        // PoK
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
        let responses3 = SchnorrProtocolPairing::prove(
            &schnorr_commitment3,        //this has the blinding factors associated to it
            &rand_sig.pairing_exponents, //this is the exponents
            &challenge,
        );

        let statement = rand_sig.pairing_statement;

        // Step 5: Verify the pairing proof

        // Compute left-hand side of verification equation
        let lhs = BBSPlusOgUtils::compute_gt_from_g1_g2_scalars::<E>(
            &rand_sig.pairing_bases_g1,
            &rand_sig.pairing_bases_g2,
            &responses3.0,
        );

        assert!(
            SchnorrProtocolPairing::verify(
                &statement3,
                &schnorr_commitment3.schnorr_commitment,
                &challenge,
                &rand_sig.pairing_bases_g1,
                &rand_sig.pairing_bases_g2,
                &responses3.0,
            ),
            "pairing protocol not verified"
        );
        println!("Pairing thru verify working");
        let rhs = schnorr_commitment3.schnorr_commitment + statement.mul(&challenge);

        // Verify pairing equation
        let is_pairing_valid = lhs.0 == rhs.0;
        assert!(is_pairing_valid, "Pairing verification failed");

        let proof = BBSPlusProofOfKnowledge {
            bases1: bases1.clone(),
            statement1,
            schnorr_commitment1: schnorr_commitment1.commited_blindings,
            schnorr_responses1: schnorr_responses1.0,
            statement2,
            schnorr_commitment2: schnorr_commitment2.commited_blindings,
            schnorr_responses2: schnorr_responses2.0,
            schnorr_commitment3: schnorr_commitment3.schnorr_commitment,
            pairing_bases_g1: rand_sig.pairing_bases_g1.clone(),
            pairing_bases_g2: rand_sig.pairing_bases_g2.clone(),
            responses3: responses3.0.clone(),
            challenge,
        };

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }

    //     responses1[0] = responses3[1]
    // responses2[0] = responses3[2]
    /// Verify a proof of knowledge of a BBS+ signature
    pub fn verify<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, ProofError> {
        // 1. Deserialize the proof
        let proof: BBSPlusProofOfKnowledge<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // 2. Verify Schnorr proof 1
        let is_schnorr1_valid = SchnorrProtocol::verify(
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

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use crate::signature::BBSPlusSignature;
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
        let signature = BBSPlusSignature::sign(&pp, &sk, &messages, &mut rng);

        // Verify the signature directly
        let is_valid = signature.verify(&pp, &pk, &messages);
        assert!(is_valid, "Signature verification failed");

        // Generate a proof of knowledge
        let proof = ProofSystem::prove_wofancy2(&pp, &pk, &signature, &messages, &mut rng)
            .expect("Failed to generate proof");

        // // Verify the proof
        // let is_proof_valid = ProofSystem::verify(&pp, &pk, &proof).expect("Failed to verify proof");

        // assert!(is_proof_valid, "Proof verification failed");
    }
}

// pub fn prove_wofancy<E: Pairing, R: Rng>(
//         pp: &PublicParams<E>,
//         pk: &PublicKey<E>,
//         signature: &BBSPlusSignature<E>,
//         messages: &[E::ScalarField],
//         rng: &mut R,
//     ) -> Result<Vec<u8>, ProofError> {
//         // Validate basic inputs
//         assert_eq!(messages.len(), pp.L, "Invalid number of messages");

//         // Extract needed generators
//         let (g1, g2) = pp.get_g1_g2();

//         // Step 1: Randomize the signature
//         let r1 = E::ScalarField::rand(rng);
//         let r2 = E::ScalarField::rand(rng);

//         // Create A1 = g1^r1 * g2^r2
//         let A1 = (g1.mul(r1) + g2.mul(r2)).into_affine();

//         // Compute A2 = A * g2_to_L[0]^r1
//         let A2 = (signature.A.into_group() + pp.g2_to_L[0].mul(r1)).into_affine();

//         // Derived values
//         let e = signature.e;
//         let s = signature.s;
//         let delta1 = r1 * e;
//         let delta2 = r2 * e;

//         // Step 2: Generate a challenge (in a real protocol this would be derived from commitments)
//         let challenge = E::ScalarField::rand(rng);

//         // Step 3: Generate blinding factors for the commitments

//         // For Proof 1: A1 = g1^r1 * g2^r2
//         let rho_r1 = E::ScalarField::rand(rng);
//         let rho_r2 = E::ScalarField::rand(rng);
//         let T1 = (g1.mul(rho_r1) + g2.mul(rho_r2)).into_affine();

//         // For Proof 2: A1^e = g1^delta1 * g2^delta2
//         let rho_delta1 = E::ScalarField::rand(rng);
//         let rho_delta2 = E::ScalarField::rand(rng);
//         let T2 = (g1.mul(rho_delta1) + g2.mul(rho_delta2)).into_affine();

//         // For Proof 3: Pairing equation
//         let rho_neg_e = E::ScalarField::rand(rng);
//         let rho_s = E::ScalarField::rand(rng);
//         let rho_messages: Vec<E::ScalarField> = (0..messages.len())
//             .map(|_| E::ScalarField::rand(rng))
//             .collect();

//         // Build pairing bases arrays
//         let mut pairing_bases_g1 = vec![
//             A2,            // For e(A2,h0)^(-e)
//             pp.g2_to_L[0], // For e(g2,w)^r1
//             pp.g2_to_L[0], // For e(g2,h0)^delta1
//             pp.g1,         // For e(g1,h0)^s
//         ];

//         let mut pairing_bases_g2 = vec![
//             pp.h0, // For e(A2,h0)^(-e)
//             pk.w,  // For e(g2,w)^r1
//             pp.h0, // For e(g2,h0)^delta1
//             pp.h0, // For e(g1,h0)^s
//         ];

//         // Add message terms
//         for i in 0..messages.len() {
//             pairing_bases_g1.push(pp.g2_to_L[i]);
//             pairing_bases_g2.push(pp.h0);
//         }

//         // Build pairing randomness vector (rho values)
//         let mut pairing_rho = vec![rho_neg_e, rho_r1, rho_delta1, rho_s];
//         pairing_rho.extend(&rho_messages);

//         // Compute T3 (pairing commitment)
//         let T3 = ProofSystem::compute_pairing_commitment::<E>(
//             &pairing_bases_g1,
//             &pairing_bases_g2,
//             &pairing_rho,
//         );

//         // Step 4: Compute responses
//         let z_r1 = rho_r1 + challenge * r1;
//         let z_r2 = rho_r2 + challenge * r2;
//         let z_delta1 = rho_delta1 + challenge * delta1;
//         let z_delta2 = rho_delta2 + challenge * delta2;
//         let z_neg_e = rho_neg_e + challenge * (-e);
//         let z_s = rho_s + challenge * s;

//         let z_messages: Vec<E::ScalarField> = rho_messages
//             .iter()
//             .zip(messages.iter())
//             .map(|(rho, &msg)| *rho + challenge * msg)
//             .collect();

//         // Build final responses vector
//         let mut pairing_responses = vec![z_neg_e, z_r1, z_delta1, z_s];
//         pairing_responses.extend(&z_messages);

//         // Compute statement for the pairing equation
//         let pair_A2_w = E::pairing(A2, pk.w);
//         let pair_g0_h0 = E::pairing(pp.g0, pp.h0);
//         let statement = PairingOutput::<E>(
//             pair_A2_w.0 * pair_g0_h0.0.inverse().expect("Pairing should be non-zero"),
//         );

//         // Step 5: Verify the pairing proof

//         // Compute left-hand side of verification equation
//         let lhs = ProofSystem::compute_pairing_commitment::<E>(
//             &pairing_bases_g1,
//             &pairing_bases_g2,
//             &pairing_responses,
//         );

//         // Compute right-hand side: T3 * statement^challenge
//         let statement_c = PairingOutput::<E>(statement.0.pow(&challenge.into_bigint().as_ref()));
//         let rhs = PairingOutput::<E>(T3.0 * statement_c.0);

//         // Verify pairing equation
//         let is_pairing_valid = lhs.0 == rhs.0;
//         assert!(is_pairing_valid, "Pairing verification failed");

//         // Verify Proof 1: A1 = g1^r1 * g2^r2
//         let lhs_proof1 = (g1.mul(z_r1) + g2.mul(z_r2)).into_affine();
//         let rhs_proof1 = (T1.into_group() + A1.mul(challenge)).into_affine();
//         let is_proof1_valid = lhs_proof1 == rhs_proof1;
//         assert!(is_proof1_valid, "Proof 1 verification failed");

//         // Verify Proof 2: A1^e = g1^delta1 * g2^delta2
//         let lhs_proof2 = (g1.mul(z_delta1) + g2.mul(z_delta2)).into_affine();
//         let A1_e = A1.mul(e).into_affine(); // This is g1^delta1 * g2^delta2
//         let rhs_proof2 = (T2.into_group() + A1_e.mul(challenge)).into_affine();
//         let is_proof2_valid = lhs_proof2 == rhs_proof2;
//         assert!(is_proof2_valid, "Proof 2 verification failed");

//         // Build the final proof structure
//         let mut responses = vec![z_r1, z_r2, z_delta1, z_delta2];
//         responses.extend(pairing_responses);

//         // let randomized_sig = BBSPlusSignatureProofCommitment { A1, A2 };

//         // let proof_commitment = vec![T1, T2];

//         // let proof = BBSPlusProofOfKnowledge {
//         //     randomized_sig,
//         //     proof_commitment,
//         //     challenge,
//         //     responses,
//         // };

//         // Serialize the proof
//         let mut serialized_proof = Vec::new();
//         // proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(serialized_proof)
//     }

//     // Helper function to compute pairing commitment
//     fn compute_pairing_commitment<E: Pairing>(
//         bases_g1: &[E::G1Affine],
//         bases_g2: &[E::G2Affine],
//         scalars: &[E::ScalarField],
//     ) -> PairingOutput<E> {
//         assert_eq!(bases_g1.len(), bases_g2.len(), "Base lengths must match");
//         assert_eq!(
//             bases_g1.len(),
//             scalars.len(),
//             "Base and scalar lengths must match"
//         );

//         // Initialize result to 1 (multiplicative identity in the target field)
//         let mut result = E::TargetField::one();

//         // Compute product of pairings
//         for i in 0..bases_g1.len() {
//             let g1_point = bases_g1[i].mul(scalars[i]).into_affine();
//             let pairing = E::pairing(g1_point, bases_g2[i]);
//             result *= pairing.0;
//         }

//         PairingOutput::<E>(result)
//     }
