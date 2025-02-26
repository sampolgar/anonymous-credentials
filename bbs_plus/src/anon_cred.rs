// Obtain
// Issue
// Show
// Verify
use crate::keygen::{PublicKey, SecretKey};
use crate::proofsystem::{BBSPlusProofOfKnowledge, CommitmentWithProof, ProofError, ProofSystem};
use crate::publicparams::PublicParams;
use crate::signature::{BBSPlusRandomizedSignature, BBSPlusSignature};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

/// Issuer's incomplete
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IssuerResponse<E: Pairing> {
    pub A: E::G1Affine,
    pub e: E::ScalarField,
    pub s_double_prime: E::ScalarField, // Issuer's blinding factor
}
pub struct AnonCredProtocol;
impl AnonCredProtocol {
    /// Obtain protocol: User creates a commitment to their messages and proves knowledge
    pub fn obtain<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> Result<(CommitmentWithProof<E>, E::ScalarField), ProofError> {
        // Generate random blinding factor s'
        let s_prime = E::ScalarField::rand(rng);

        // cm = [s_', m_1, ...., m_L]
        // cm = h_0^s' h_1^m_1 ... h_L^m_L

        let commitment_proof =
            ProofSystem::create_commitment_proof(pp, pk, messages, &s_prime, rng)?;

        Ok((commitment_proof, s_prime))
    }
    /// Issue protocol: Issuer verifies the proof and issues a signature
    pub fn issue<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        sk: &SecretKey<E>,
        pk: &PublicKey<E>,
        commitment_proof: &CommitmentWithProof<E>,
        rng: &mut R,
    ) -> Result<IssuerResponse<E>, ProofError> {
        // Verify the proof of knowledge using ProofSystem
        let is_valid = ProofSystem::verify_commitment_proof(pp, pk, commitment_proof)?;

        if !is_valid {
            return Err(ProofError::VerificationFailed);
        }

        // Generate random values for the signature
        let e = E::ScalarField::rand(rng);
        let s_double_prime = E::ScalarField::rand(rng);

        // Compute A = (g₁ · g₂^s'' · Cm)^(1/(e+x))
        let base = pp.g1 + pk.h0 * s_double_prime + commitment_proof.commitment;
        let exponent = (sk.x + e).inverse().unwrap();
        let A = (base * exponent).into_affine();

        Ok(IssuerResponse {
            A,
            e,
            s_double_prime,
        })
    }

    /// Complete signature: User combines issuer response with their secrets to get a valid signature
    pub fn complete_signature<E: Pairing>(
        s_prime: &E::ScalarField,
        issuer_response: &IssuerResponse<E>,
    ) -> BBSPlusSignature<E> {
        // Compute s = s' + s''
        let s = *s_prime + issuer_response.s_double_prime;

        // Construct the signature (A, e, s)
        BBSPlusSignature {
            A: issuer_response.A,
            e: issuer_response.e,
            s,
        }
    }

    // pub fn Obtain
    // pub fn Issue
    pub fn show<E: Pairing, R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        signature: &BBSPlusSignature<E>,
        messages: &[E::ScalarField],
        rng: &mut R,
    ) -> (BBSPlusRandomizedSignature<E>, Result<Vec<u8>, ProofError>) {
        // Rerandomize the signature
        let randomized_signature = signature.rerandomize(&pp, &pk, &messages, rng);

        let proof = ProofSystem::bbs_plus_prove(&pp, &randomized_signature, &pk, &messages, rng)
            .expect("Failed to generate proof");

        // Return the randomized signature and the proof result
        (randomized_signature, Ok(proof))
    }

    pub fn verify<E: Pairing>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        serialized_proof: &[u8],
    ) -> bool {
        // Verify the proof
        let verification_result = ProofSystem::bbs_plus_verify_proof(&pp, &pk, &serialized_proof)
            .expect("Failed to verify proof");

        assert!(verification_result, "Proof verification failed");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::TestSetup;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::test_rng;

    #[test]
    fn test_manual_commitment_with_blind_verify() {
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 3);

        // 1. Create a commitment manually
        let s_prime = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);

        // Manually construct commitment: h0^s_prime * h1^m1 * ... * hL^mL
        let mut manual_commitment = setup.pk.h0 * s_prime;
        for i in 0..setup.messages.len() {
            manual_commitment += setup.pk.h1hL[i] * setup.messages[i];
        }

        let manual_commitment_affine = manual_commitment.into_affine();

        // 2. Generate a signature for this commitment
        let e = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let s_double_prime = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);

        // Calculate A as in the issuer's response
        let base = setup.pp.g1 + setup.pk.h0 * s_double_prime + manual_commitment;
        let exponent = (setup.sk.x + e).inverse().unwrap();
        let A = (base * exponent).into_affine();

        // 3. User completes the signature
        let s = s_prime + s_double_prime;
        let signature = BBSPlusSignature { A, e, s };

        // Additional debug info
        println!("manual_commitment: {:?}", manual_commitment_affine);
        println!("signature.A: {:?}", signature.A);
        println!("signature.e: {:?}", signature.e);
        println!("signature.s: {:?}", signature.s);
        println!("s_prime: {:?}", s_prime);
        println!("s_double_prime: {:?}", s_double_prime);

        // 4. Use blind verification
        let blind_verify = signature.verify_blind(&setup.pp, &setup.pk, &manual_commitment_affine);

        assert!(
            blind_verify,
            "Blind verification failed with manually constructed commitment"
        );
    }

    #[test]
    fn test_obtain_issue_show_verify() {
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 4);

        // 1. Obtain: User creates commitment and proof
        // cm =
        let (commitment_proof, s_prime) =
            AnonCredProtocol::obtain(&setup.pp, &setup.pk, &setup.messages, &mut rng)
                .expect("Failed to create commitment");

        // // test commitment
        // // cm = h_0^s' h_1^m_1 ... h_L^m_L=
        // let mut exponents = vec![s_prime];
        // exponents.extend(setup.messages.iter().cloned());

        // let bases = setup.pk.get_all_h();

        // 2. Issue: Issuer verifies and creates signature components
        let issuer_response =
            AnonCredProtocol::issue(&setup.pp, &setup.sk, &setup.pk, &commitment_proof, &mut rng)
                .expect("Failed to issue credential");

        // A =(g_0 . h_0^s'' . cm) 1/e+x

        // 3. User completes the signature
        let signature = AnonCredProtocol::complete_signature(&s_prime, &issuer_response);

        let isvalid = signature.verify_blind(&setup.pp, &setup.pk, &commitment_proof.commitment);
        assert!(isvalid, "signature verify blind not valid");
        // 4. Show: User shows the credential
        let (randomized_signature, proof_result) =
            AnonCredProtocol::show(&setup.pp, &setup.pk, &signature, &setup.messages, &mut rng);

        // 5. Verify: Verifier checks the credential
        let proof = proof_result.expect("Failed to generate proof");
        let verification_result = AnonCredProtocol::verify(&setup.pp, &setup.pk, &proof);
        assert!(verification_result, "Proof verification failed");
    }

    #[test]
    fn test() {
        let mut rng = test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, 4);

        // Call the show function
        let (randomized_signature, proof_result) = AnonCredProtocol::show(
            &setup.pp,
            &setup.pk,
            &setup.signature,
            &setup.messages,
            &mut rng,
        );

        // Ensure the proof generation was successful
        let proof = proof_result.expect("Failed to generate proof");

        // Verify the proof
        let verification_result = AnonCredProtocol::verify(&setup.pp, &setup.pk, &proof);
        assert!(verification_result, "Proof verification failed");
    }
}
