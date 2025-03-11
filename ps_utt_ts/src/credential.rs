// Includes user operations and aggregation (since users are responsible for combining shares):
// Creating commitments
// Managing blinding factors
// Aggregating signature shares
// Unblinding signatures
use crate::commitment::{Commitment, CommitmentError, CommitmentProof};
// use crate::signature::{BlindSignature, SignatureShare, ThresholdSignatureError};
use crate::symmetric_commitment::{SymmetricCommitment, SymmetricCommitmentKey};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use std::iter;

/// Commitment to a single message with its proof
pub struct CredentialCommitments<E: Pairing> {
    pub h: E::G1Affine,
    pub commitments: Vec<E::G1Affine>,
    pub proofs: Vec<Vec<u8>>,
}

/// Credential with multiple attributes
pub struct Credential<E: Pairing> {
    pub ck: SymmetricCommitmentKey<E>,
    messages: Vec<E::ScalarField>,
    blinding_factors: Vec<E::ScalarField>,
    h: Option<E::G1Affine>, // Base for the signature
}

impl<E: Pairing> Credential<E> {
    pub fn new(ck: SymmetricCommitmentKey<E>) -> Self {
        Self {
            ck: ck,
            messages: Vec::new(),
            blinding_factors: Vec::new(),
            h: None,
        }
    }

    pub fn set_attributes(&mut self, messages: Vec<E::ScalarField>) {
        self.messages = messages;
    }

    // commit to each message attribute individually for threshold sig
    pub fn compute_commitments(
        &mut self,
        rng: &mut impl Rng,
    ) -> Result<CredentialCommitments<E>, CommitmentError> {
        if self.messages.is_empty() {
            return Err((CommitmentError::InvalidComputeCommitment));
        }

        // create h for sig
        let h = self.ck.g.mul(E::ScalarField::rand(rng)).into_affine();
        self.h = Some(h);

        // loop through         // Initialize vectors to store commitments and proofs
        let mut commitments: Vec<E::G1Affine> = Vec::with_capacity(self.messages.len());
        let mut commitment_proofs: Vec<Vec<u8>> = Vec::with_capacity(self.messages.len());

        // Generate commitment and proof for each message
        for i in 0..self.messages.len() {
            let current_cm = Commitment::<E>::new(&h, &self.ck.g, &self.messages[i], None, rng);

            // Store the commitment
            commitments.push(current_cm.cm);

            // Generate and store the proof
            match current_cm.prove(rng) {
                Ok(proof) => commitment_proofs.push(proof),
                Err(err) => return Err(err),
            }
        }

        // Return the commitments and proofs in a CredentialCommitments struct
        Ok(CredentialCommitments {
            h,
            commitments,
            proofs: commitment_proofs,
        })
    }

    /// Prepare credential requests with unique commitments for each signer
    pub fn prepare_credential_requests(
        &mut self,
        num_signers: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<CredentialCommitments<E>>, CommitmentError> {
        let mut commitment_requests = Vec::with_capacity(num_signers);

        for _ in 0..num_signers {
            let commitments = self.compute_commitments(rng)?;
            commitment_requests.push(commitments);
        }

        Ok(commitment_requests)
    }
}
