use crate::commitment::Commitment;
use crate::keygen::{gen_keys, SecretKey, VerificationKey};
use crate::proofsystem::{CommitmentProof, CommitmentProofError, CommitmentProofs};
use crate::publicparams::PublicParams;
use crate::signature::PSUTTSignature;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
// use std::time::Instant;

/// Presentation of a credential with G1 and G2 elements
pub struct ShowCredential<E: Pairing> {
    pub randomized_signature: PSUTTSignature<E>,
    pub cmg1: E::G1Affine,
    pub cmg2: E::G2Affine,
    pub proof: Vec<u8>,
}

/// User credential containing a secret key and commitment
pub struct UserCred<E: Pairing> {
    pub usk: E::ScalarField,
    pub commitment: Commitment<E>,
}

impl<E: Pairing> UserCred<E> {    pub fn new(
        pp: &PublicParams<E>,
        messages: &Vec<E::ScalarField>,
        usk: E::ScalarField,
    ) -> UserCred<E> {
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }

    /// Create a new user credential with random attributes
    pub fn new_random_messages(pp: &PublicParams<E>) -> UserCred<E> {
        let mut rng = ark_std::test_rng();
        let usk = E::ScalarField::rand(&mut rng);
        let messages: Vec<E::ScalarField> =
            (0..pp.n).map(|_| E::ScalarField::rand(&mut rng)).collect();
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }
}

/// Standard anonymous credential protocol
pub struct AnonCredProtocol<E: Pairing> {
    pub pp: PublicParams<E>,
    sk: SecretKey<E>,
    vk: VerificationKey<E>,
}

impl<E: Pairing> AnonCredProtocol<E> {
    /// Create a new protocol instance with specified message count
    pub fn new(n: usize, rng: &mut impl Rng) -> Self {
        let context = E::ScalarField::rand(rng);
        let pp = PublicParams::<E>::new(&n, &context, rng);
        let (sk, vk) = gen_keys(&pp, rng);
        Self { pp, sk, vk }
    }

    /// User generates proof of knowledge for obtaining a credential
    pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
        CommitmentProofs::pok_commitment_prove(&user_cred.commitment)
    }

    /// Issuer verifies proof and issues credential
    pub fn issue(
        &self,
        serialized_proof: &[u8],
    ) -> Result<PSUTTSignature<E>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Verify proof of knowledge
        if !CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)? {
            return Err(CommitmentProofError::InvalidProof);
        }

        // Deserialize proof to access the commitment
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Sign the commitment
        Ok(PSUTTSignature::sign(
            &self.pp,
            &self.sk,
            &proof.commitment,
            &mut rng,
        ))
    }

    /// User shows credential by rerandomizing and creating presentation
    pub fn show<R: Rng>(
        &self,
        commitment: &Commitment<E>,
        signature: &PSUTTSignature<E>,
        rng: &mut R,
    ) -> Result<ShowCredential<E>, CommitmentProofError> {
        // Generate random values for rerandomization
        // let start_show = Instant::now();
        let r_delta = E::ScalarField::rand(rng);
        let u_delta = E::ScalarField::rand(rng);

        // Rerandomize the commitment and signature
        let randomized_commitment = commitment.create_randomized(&r_delta);

        let randomized_signature = signature.rerandomize(&self.pp, &r_delta, &u_delta);

        let serialized_proof = CommitmentProofs::pok_commitment_prove(&randomized_commitment)?;
        // Create proof of knowledge for the rerandomized commitment
        let show_cred = ShowCredential {
            randomized_signature,
            cmg1: randomized_commitment.cmg1,
            cmg2: randomized_commitment.cmg2,
            proof: serialized_proof,
        };
        // let duration = start_show.elapsed();
        // println!("Time to show PS_UTT_G1: {:?}", duration);

        Ok(show_cred)
    }

    /// Verifier checks credential presentation
    pub fn verify(&self, cred_show: &ShowCredential<E>) -> Result<bool, CommitmentProofError> {
        // Verify proof of knowledge
        // let start_verify = Instant::now();
        if !CommitmentProofs::pok_commitment_verify::<E>(&cred_show.proof)? {
            return Ok(false);
        }

        // Verify signature
        let is_valid = cred_show.randomized_signature.verify_with_pairing_checker(
            &self.pp,
            &self.vk,
            &cred_show.cmg1,
            &cred_show.cmg2,
        );
        // let duration = start_verify.elapsed();
        // println!("Time to verify PS_UTT_G1: {:?}", duration);
        Ok(is_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_psutt_credential_lifecycle() {
        // Setup phase
        let mut rng = test_rng();
        let message_count = 5;
        let protocol = AnonCredProtocol::<Bls12_381>::new(message_count, &mut rng);

        // User phase - generate attributes and commitment
        let user_attributes: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let user_blinding = Fr::rand(&mut rng);
        let user_cred = UserCred::<Bls12_381>::new(&protocol.pp, &user_attributes, user_blinding);

        // Obtain phase - user creates proof of knowledge
        let proof = protocol
            .obtain(&user_cred)
            .expect("Failed to generate proof");

        // Issue phase - issuer verifies proof and issues credential
        let signature = protocol.issue(&proof).expect("Failed to issue credential");

        // Verify original signature
        assert!(
            signature.verify_with_pairing_checker(
                &protocol.pp,
                &protocol.vk,
                &user_cred.commitment.cmg1,
                &user_cred.commitment.cmg2
            ),
            "Original signature verification failed"
        );

        // Show phase - user creates presentation
        let presentation = protocol
            .show(&user_cred.commitment, &signature, &mut rng)
            .expect("Failed to generate credential presentation");

        // Verify phase
        let is_valid = protocol
            .verify(&presentation)
            .expect("Verification process failed");

        assert!(is_valid, "Credential verification failed");
    }
}
