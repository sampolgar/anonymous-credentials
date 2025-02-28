use crate::commitment::Commitment;
use crate::keygen::{gen_keys, PublicKey, SecretKey};
use crate::proofsystem::{CommitmentProof, CommitmentProofs, ProofError};
use crate::publicparams::PublicParams;
use crate::signature::PSSignature;
// use crate::test_helpers::{create_ps_with_userid, PSTestSetup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use utils::helpers::Helpers;

/// User credential containing attributes and commitment
pub struct UserCred<E: Pairing> {
    pub t: E::ScalarField,
    pub messages: Vec<E::ScalarField>,
    pub commitment: Commitment<E>,
}
pub struct ShowCredential<E: Pairing> {
    pub randomized_signature: (E::G1Affine, E::G1Affine),
    pub proof: Vec<u8>,
}

/// Anonymous credential protocol for PS signatures
pub struct PSAnonCredProtocol<E: Pairing> {
    pub pp: PublicParams<E>,
    pub pk: PublicKey<E>,
    sk: SecretKey<E>,
}

impl<E: Pairing> UserCred<E> {
    /// Create a new user credential with provided attributes
    pub fn new(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        t: E::ScalarField,
    ) -> Self {
        let commitment = Commitment::new(&pp, &pk, &messages, &t);

        Self {
            t,
            messages: messages.to_vec(),
            commitment,
        }
    }

    /// Create a new user credential with random attributes
    pub fn new_random_messages(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        message_count: usize,
    ) -> Self {
        let mut rng = ark_std::test_rng();
        let t = E::ScalarField::rand(&mut rng);
        let messages: Vec<E::ScalarField> = (0..message_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        Self::new(pp, pk, &messages, t)
    }
}

impl<E: Pairing> PSAnonCredProtocol<E> {
    /// Create a new protocol instance with specified message count
    pub fn new(n: usize, rng: &mut impl Rng) -> Self {
        let context = E::ScalarField::rand(rng);
        let pp = PublicParams::<E>::new(&n, &context, rng);
        let (sk, pk) = gen_keys(&pp, rng);
        Self { pp, pk, sk }
    }

    /// User generates proof of knowledge for obtaining a credential
    pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, ProofError> {
        // Generate proof of knowledge
        CommitmentProofs::pok_commitment_prove(&user_cred.commitment)
    }

    /// Issuer verifies proof and issues credential
    pub fn issue<R: Rng>(
        &self,
        user_commitment: &E::G1Affine,
        serialized_proof: &[u8],
        rng: &mut R,
    ) -> Result<PSSignature<E>, ProofError> {
        // Verify proof of knowledge
        if !CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)? {
            return Err(ProofError::InvalidProof);
        }
        // Deserialize proof to access the commitment
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Issue blind signature
        let blind_signature =
            PSSignature::blind_sign(&self.pp, &self.pk, &self.sk, user_commitment, rng);

        Ok(blind_signature)
    }

    /// User completes the blind signature with their blinding factor
    pub fn complete_signature(
        blind_signature: &PSSignature<E>,
        t: &E::ScalarField,
    ) -> PSSignature<E> {
        blind_signature.unblind(t)
    }

    /// User shows credential by creating a randomized signature and proof
    pub fn show<R: Rng>(
        &self,
        signature: &PSSignature<E>,
        user_cred: &UserCred<E>,
        rng: &mut R,
    ) -> Result<ShowCredential<E>, ProofError> {
        // Randomize the signature
        let r = E::ScalarField::rand(rng);
        let t = E::ScalarField::rand(rng);
        let randomized_signature = signature.rerandomize(&r, &t);

        // Generate proof of knowledge
        

        // Ok(ShowCredential {
        //     randomized_signature: (randomized_signature.sigma1, randomized_signature.sigma2),
        //     proof,
        // })
    }

    // /// Verifier checks credential presentation
    // pub fn verify(&self, show_credential: &ShowCredential<E>) -> Result<bool, ProofError> {
    //     // Create a verification setup
    //     let verification_setup = PSTestSetup {
    //         pk: self.pk.clone(),
    //         sk: self.sk.clone(),
    //         messages: Vec::new(), // The messages will be proven in the proof
    //         signature: Signature {
    //             sigma1: show_credential.randomized_signature.0,
    //             sigma2: show_credential.randomized_signature.1,
    //         },
    //     };

    //     // Verify the proof of knowledge
    //     let is_valid = PSProofs::verify_knowledge(&verification_setup, &show_credential.proof);

    //     Ok(is_valid)
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_ps_anoncred_lifecycle() {
        // Setup phase
        let mut rng = test_rng();
        let message_count = 5;
        let protocol = PSAnonCredProtocol::<Bls12_381>::new(message_count, &mut rng);

        // User phase - generate attributes and commitment
        let user_cred =
            UserCred::<Bls12_381>::new_random_messages(&protocol.pp, &protocol.pk, message_count);

        // Obtain phase - user creates proof
        let proof = protocol.obtain(&user_cred).unwrap();

        // Issue phase - issuer issues credential
        let blind_signature = protocol
            .issue(&user_cred.commitment.commitment, &proof, &mut rng)
            .unwrap();

        // User unblinds the signature
        let signature = PSAnonCredProtocol::complete_signature(&blind_signature, &user_cred.t);

        // Show phase - user creates presentation
        let presentation = protocol.show(&signature, &user_cred, &mut rng).unwrap();

        // // Verify phase
        // let is_valid = protocol.verify(&presentation).unwrap();

        // assert!(is_valid, "Credential verification failed");
    }
}
