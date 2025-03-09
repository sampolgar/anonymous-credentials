// Includes user operations and aggregation (since users are responsible for combining shares):
// Creating commitments
// Managing blinding factors
// Aggregating signature shares
// Unblinding signatures

use crate::commitment::{Commitment, CommitmentError, CommitmentKey};
use crate::publicparams::PublicParams;
use crate::signature_ts::{BlindSignature, SignatureShare, ThresholdSignatureError};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Mul;
use ark_std::rand::Rng;

/// Commitment to a single message with its proof
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct MessageCommitment<E: Pairing> {
    pub commitment: Commitment<E>,
    pub proof: Vec<u8>,
}

/// Collection of commitments for a credential's attributes
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CredentialCommitments<E: Pairing> {
    pub message_commitments: Vec<MessageCommitment<E>>,
    pub h: E::G1Affine, // Base for the signature
}

/// Credential with multiple attributes
pub struct Credential<E: Pairing> {
    pub pp: PublicParams<E>,
    pub ck: CommitmentKey<E>,
    messages: Vec<E::ScalarField>,
    blinding_factors: Vec<E::ScalarField>,
    h: Option<E::G1Affine>, // Base for the signature
}

impl<E: Pairing> Credential<E> {
    pub fn new(pp: &PublicParams<E>, ck: &CommitmentKey<E>) -> Self {
        Self {
            pp,
            ck,
            message: None,
            blinding_factor: None,
            h: None,
        }
    }

    pub fn set_attributes(&mut self, messages: Vec<E::ScalarField>) {
        self.messages = messages;
    }

    // commit to each message attribute individually for threshold sig
    pub fn compute_commitments(
        &self,
        rng: &mut impl Rng,
    ) -> Result<CredentialCommitments<E>, CommitmentError> {
        if self.messages.is_empty() {
            return Err((CommitmentError::InvalidComputeCommitment));
        }
        
        // create h for sig
        let h = self.pp.g.mul(E::ScalarField::rand(rng)).into_affine();
        self.h = Some(h);

        
    }
}
