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
        }
    }

    pub fn set_attributes(&mut self, messages: Vec<E::ScalarField>) {
        self.messages = messages;
    }

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

    pub fn attach_signature(&mut self, sig: ThresholdSignature<E>) {
        self.sig = Some(sig);
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

    /// Prepare credential requests with unique commitments for each signer
    pub fn prepare_credential_requests(
        &mut self,
        num_signers: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<CredentialCommitments<E>>, CommitmentError> {
        let mut commitment_requests = Vec::with_capacity(num_signers);

        for _ in 0..num_signers {
            let commitments = self.compute_commitments_per_m(rng)?;
            commitment_requests.push(commitments);
        }

        Ok(commitment_requests)
    }

    /// Request signatures from signers until threshold is reached
    pub fn request_signatures(
        credential_requests: &[CredentialCommitments<E>],
        signers: &[Signer<E>],
        t: usize,
    ) -> Result<(Vec<(usize, PartialSignature<E>)>, E::G1Affine), SignatureError> {
        let h = credential_requests[0].h;
        let mut shares = Vec::new();
        for (i, signer) in signers.iter().enumerate().take(t + 1) {
            // break if we have enough shares
            if shares.len() == t + 1 {
                break;
            }

            let curr_request = &credential_requests[i];
            let curr_share =
                signer.sign_share(&curr_request.commitments, &curr_request.proofs, &h)?;
            shares.push((i, curr_share));
        }

        if shares.len() < t + 1 {
            return Err(SignatureError::InsufficientShares {
                needed: t + 1,
                got: shares.len(),
            });
        }
        Ok((shares, h))
    }

    /// this is the anonymous credential `show` protocol. generates proof for commitment
    pub fn show(
        &self,
        rng: &mut impl Rng,
    ) -> Result<(ThresholdSignature<E>, E::G1Affine, E::G2Affine, Vec<u8>), CredentialError> {
        // Check signature exists
        let sig = self.sig.as_ref().ok_or(CredentialError::MissingSignature(
            "Signature must be attached before randomization".to_string(),
        ))?;

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
}
