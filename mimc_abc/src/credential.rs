use crate::commitment::{Commitment, CommitmentKey};
use crate::proof::CommitmentProof;
use crate::public_params::PublicParams;
use crate::signature::{Signature, VerificationKey};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialState {
    Initialized, // Just created with attributes
    Committed,   // Commitments generated
    Signed,      // Has valid signature
    Randomized,  // Has been shown/randomized
}

pub struct Credential<E: Pairing> {
    pub commitment: Commitment<E>,
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
    signature: Option<Signature<E>>,
    state: CredentialState,
}

impl<E: Pairing> Credential<E> {
    pub fn new(
        ck: &CommitmentKey<E>,
        pp: &PublicParams<E>,
        messages: &[E::ScalarField],
        r: E::ScalarField,
    ) -> Self {
        let commitment = ck.commit(pp, messages, &r);

        Self {
            commitment,
            messages: messages.to_vec(),
            r,
            signature: None,
            state: CredentialState::Committed,
        }
    }

    // Method for creating proof for issuance
    pub fn prove_commitment(&self, pp: &PublicParams<E>, rng: &mut impl Rng) -> CommitmentProof<E> {
        CommitmentProof::prove(pp, &self.commitment, &self.messages, &self.r, rng)
    }

    // Add signature after issuance
    pub fn add_signature(&mut self, signature: Signature<E>) {
        self.signature = Some(signature);
        self.state = CredentialState::Signed;
    }

    // get messages from credential
    pub fn get_messages(&self) -> &Vec<E::ScalarField> {
        &self.messages
    }

    // Randomize credential for showing
    pub fn show(
        &self,
        pp: &PublicParams<E>,
        delta_r: &E::ScalarField,
        delta_u: &E::ScalarField,
        rng: &mut impl Rng,
    ) -> ShowCredential<E> {
        // Only allow randomization if credential is signed
        if self.state != CredentialState::Signed || self.signature.is_none() {
            panic!("Cannot randomize unsigned credential");
        }

        // Create randomized commitment
        let new_r = self.r + delta_r;

        // Randomize signature
        let randomized_signature = self.signature.as_ref().unwrap().randomize(delta_r, delta_u);

        let randomized_commitment = self.commitment.randomize(pp, delta_r);

        // Create proof for randomized credential
        let proof =
            CommitmentProof::prove(&pp, &randomized_commitment, &self.messages, &new_r, rng);

        // Return presentation object
        ShowCredential {
            randomized_signature,
            randomized_commitment,
            proof,
            r_new: new_r,
        }
    }

    // Get user ID (useful for many applications)
    pub fn get_user_id(&self) -> &E::ScalarField {
        &self.messages[0]
    }

    // Verify signature directly on the credential
    pub fn verify(&self, pp: &PublicParams<E>, vk: &VerificationKey<E>) -> bool {
        if let Some(sig) = &self.signature {
            vk.verify(sig, &self.commitment, &pp)
        } else {
            false
        }
    }
}

// Presentation object for shown credentials
#[derive(Clone)]
pub struct ShowCredential<E: Pairing> {
    pub randomized_signature: Signature<E>,
    pub randomized_commitment: Commitment<E>,
    pub proof: CommitmentProof<E>,
    pub r_new: E::ScalarField,
}

impl<E: Pairing> ShowCredential<E> {
    pub fn verify(&self, pp: &PublicParams<E>, vk: &VerificationKey<E>) -> bool {
        // First verify the proof
        if !self.proof.verify() {
            println!("Show Cred Proof failed");
            return false;
        }

        // Then verify the signature
        if !vk.verify(&self.randomized_signature, &self.randomized_commitment, &pp) {
            println!("Signature failed");
            return false;
        }
        true
    }
}
