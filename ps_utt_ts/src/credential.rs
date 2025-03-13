use crate::commitment::{Commitment, CommitmentProof};
use crate::errors::{CommitmentError, CredentialError, SignatureError};
use crate::signature::{PartialSignature, ThresholdSignature};
use crate::signer::Signer;
use crate::symmetric_commitment::{SymmetricCommitment, SymmetricCommitmentKey};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use ark_std::Zero;
use std::iter;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialState {
    Initialized, // Just created with attributes
    Committed,   // Commitments generated
    Signed,      // Has valid signature
    Randomized,  // Has been shown/randomized
}
/// Commitment to a single message with its proof
pub struct CredentialCommitments<E: Pairing> {
    pub h: E::G1Affine,
    pub commitments: Vec<E::G1Affine>,
    pub proofs: Vec<Vec<u8>>,
}

pub struct Credential<E: Pairing> {
    pub ck: SymmetricCommitmentKey<E>,
    pub cm: SymmetricCommitment<E>,
    messages: Vec<E::ScalarField>,
    blindings: Vec<E::ScalarField>,
    h: E::G1Affine,
    sig: Option<ThresholdSignature<E>>,
    pub context: E::ScalarField, // context for the credential like an id
    pub state: CredentialState,
    pub metadata: Option<String>, // testing for benchmarking
}

impl<E: Pairing> Credential<E> {
    pub fn new(
        ck: SymmetricCommitmentKey<E>,
        messages: Option<&[E::ScalarField]>,
        rng: &mut impl Rng,
    ) -> Self {
        let num_messages = ck.ck.len();
        // Generate random messages if none are provided
        let messages = match messages {
            Some(msgs) => msgs.to_vec(),
            None => iter::repeat_with(|| E::ScalarField::rand(rng))
                .take(num_messages)
                .collect(),
        };
        // gen h
        let h = E::G1Affine::rand(rng);
        // gen cm
        let cm = SymmetricCommitment::<E>::new(&ck, &messages, &E::ScalarField::zero());

        Self {
            ck,
            cm,
            messages,
            blindings: Vec::new(),
            h,
            sig: None,
            context: E::ScalarField::rand(rng),
            state: CredentialState::Initialized,
            metadata: None,
        }
    }

    pub fn set_attributes(&mut self, messages: Vec<E::ScalarField>) {
        self.messages = messages;
    }

    // set the symmetric commitment, at the start it will be CM.Com([m_1, ..., m_L], 0)
    pub fn set_symmetric_commitment(&mut self) {
        let zero = E::ScalarField::zero();
        let cm = SymmetricCommitment::<E>::new(&self.ck, &self.messages, &zero);
        self.cm = cm;
    }

    pub fn get_messages(&self) -> &Vec<E::ScalarField> {
        &self.messages
    }

    pub fn get_blinding_factors(&self) -> &Vec<E::ScalarField> {
        &self.blindings
    }

    // commit to each message attribute individually for threshold sig
    //  h_1^m_1 g_1^r_1 * h_2^m_2 g_2^r_2
    //  m_1, ..., m_L
    //  r_1, ..., r_L
    pub fn compute_commitments_per_m(
        &mut self,
        rng: &mut impl Rng,
    ) -> Result<CredentialCommitments<E>, CommitmentError> {
        if self.messages.is_empty() {
            return Err(CommitmentError::InvalidComputeCommitment);
        }

        // loop through         // Initialize vectors to store commitments and proofs
        let mut commitments: Vec<E::G1Affine> = Vec::with_capacity(self.messages.len());
        let mut commitment_proofs: Vec<Vec<u8>> = Vec::with_capacity(self.messages.len());

        // Generate commitment and proof for each message
        for i in 0..self.messages.len() {
            let current_cm =
                Commitment::<E>::new(&self.h, &self.ck.g, &self.messages[i], None, rng);

            // store the randomness
            self.blindings.push(current_cm.exponents[1]);
            // Store the commitment
            commitments.push(current_cm.cm);

            self.state = CredentialState::Committed;

            // Generate and store the proof
            match current_cm.prove(rng) {
                Ok(proof) => commitment_proofs.push(proof),
                Err(err) => return Err(err),
            }
        }

        // Return the commitments and proofs in a CredentialCommitments struct
        Ok(CredentialCommitments {
            h: self.h,
            commitments,
            proofs: commitment_proofs,
        })
    }

    pub fn attach_signature(&mut self, sig: ThresholdSignature<E>) {
        self.state = CredentialState::Signed;
        self.sig = Some(sig);
    }

    /// this is the anonymous credential `show` protocol. generates proof for commitment
    pub fn show(
        &self,
        rng: &mut impl Rng,
    ) -> Result<(ThresholdSignature<E>, E::G1Affine, E::G2Affine, Vec<u8>), CredentialError> {
        // Check signature exists
        if self.state != CredentialState::Signed {
            return Err(CredentialError::InvalidState(
                "Credential must be signed before showing".to_string(),
            ));
        }

        let sig = self.sig.as_ref().unwrap();
        // Randomize signature
        let (randomized_sig, r_delta) = sig.randomize(rng);

        // Randomize commitment
        let sym_cm = self.cm.clone();
        let rand_sym_cm = sym_cm.randomize(&r_delta);

        // Generate proof
        let proof = rand_sym_cm
            .clone()
            .prove(rng)
            .map_err(CredentialError::ProofGenerationFailed)?;
        Ok((randomized_sig, rand_sym_cm.cm, rand_sym_cm.cm_tilde, proof))
    }

    // Helper methods for multi-credential management
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}
