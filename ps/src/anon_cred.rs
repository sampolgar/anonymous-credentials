use crate::commitment::Commitment;
use crate::keygen::{gen_keys, PublicKey, SecretKey};
use crate::proofsystem::{CommitmentProof, CommitmentProofs, ProofError, SignatureProofs};
use crate::publicparams::PublicParams;
use crate::signature::PSSignature;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

/// User credential containing attributes and blinding factor
pub struct UserCred<E: Pairing> {
    pub t: E::ScalarField,
    pub messages: Vec<E::ScalarField>,
}

/// Presentation of a credential with proof
pub struct ShowCredential {
    pub proof: Vec<u8>,
}

/// Anonymous credential protocol for PS signatures
pub struct PSAnonCredProtocol<E: Pairing> {
    pub pp: PublicParams<E>,
    pub pk: PublicKey<E>,
    sk: SecretKey<E>, // Private to prevent unauthorized issuance
}

impl<E: Pairing> UserCred<E> {
    /// Create a new user credential with provided attributes
    pub fn new(messages: &[E::ScalarField], t: E::ScalarField) -> Self {
        Self {
            t,
            messages: messages.to_vec(),
        }
    }

    /// Create a new user credential with random attributes
    pub fn new_random_messages(message_count: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let t = E::ScalarField::rand(&mut rng);
        let messages: Vec<E::ScalarField> = (0..message_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();

        Self::new(&messages, t)
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
        let commitment = Commitment::new(&self.pp, &self.pk, &user_cred.messages, &user_cred.t);
        CommitmentProofs::pok_commitment_prove(&commitment)
    }

    /// Issuer verifies proof and issues credential
    pub fn issue<R: Rng>(
        &self,
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

        // Issue blind signature - using proof.statement as in the original code
        let blind_signature =
            PSSignature::blind_sign(&self.pp, &self.pk, &self.sk, &proof.statement, rng);

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
        _rng: &mut R, // Unused parameter but kept for API consistency
    ) -> Result<ShowCredential, ProofError> {
        let proof =
            SignatureProofs::pok_signature(&self.pp, &self.pk, &user_cred.messages, &signature);

        Ok(ShowCredential { proof })
    }

    /// Verifier checks credential presentation
    pub fn verify(&self, show_credential: &ShowCredential) -> Result<bool, ProofError> {
        Ok(SignatureProofs::verify_knowledge(
            &self.pp,
            &self.pk,
            &show_credential.proof,
        ))
    }
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

        // User phase - generate attributes
        let user_cred = UserCred::<Bls12_381>::new_random_messages(message_count);

        // Obtain phase - user creates proof
        let proof = protocol.obtain(&user_cred).unwrap();

        // Issue phase - issuer issues credential
        let blind_signature = protocol.issue(&proof, &mut rng).unwrap();

        // User unblinds the signature
        let signature = PSAnonCredProtocol::complete_signature(&blind_signature, &user_cred.t);

        // Show phase - user creates presentation
        let presentation = protocol.show(&signature, &user_cred, &mut rng).unwrap();

        // Verify phase
        assert!(
            protocol.verify(&presentation).unwrap(),
            "Credential verification failed"
        );
    }
}
