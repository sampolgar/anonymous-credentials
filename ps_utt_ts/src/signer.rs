// signer.rs
// Includes signer operations:

// Verifying commitment proofs
// Generating signature shares
// signer.rs
use crate::commitment::SymmetricCommitmentKey;
use crate::commitment::{CommitmentError, CredentialCommitments};
use crate::keygen::{SecretKeyShare, VerificationKeyShare};
use crate::signature::{SignatureShare, ThresholdSignatureError};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_std::ops::Mul;

/// A signer in the threshold signature scheme
pub struct Signer<E: Pairing> {
    pub ck: SymmetricCommitmentKey<E>,
    /// Signer's secret key share
    pub sk_share: SecretKeyShare<E>,
    /// Signer's verification key share
    pub vk_share: VerificationKeyShare<E>,
}

impl<E: Pairing> Signer<E> {
    /// Create a new signer with key shares
    pub fn new(
        params: PublicParams<E>,
        ck: SymmetricCommitmentKey<E>,
        sk_share: SecretKeyShare<E>,
        vk_share: VerificationKeyShare<E>,
    ) -> Self {
        Self {
            params,
            ck,
            sk_share,
            vk_share,
        }
    }

    // Same methods as before...
}
