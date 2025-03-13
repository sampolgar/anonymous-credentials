use crate::credential::{Credential, CredentialCommitments};
use crate::errors::{CredentialError, SignatureError, VerificationError};
use crate::keygen::VerificationKeyShare;
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::signature::compute_lagrange_coefficient;
use crate::signature::{PartialSignature, ThresholdSignature};
use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use crate::user::User;
use crate::verifier::Verifier;
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
pub struct Protocol;

impl Protocol {
    /// Setup generates the system parameters and keys
    pub fn setup<E: Pairing>(
        threshold: usize,
        num_signers: usize,
        num_attributes: usize,
        rng: &mut impl Rng,
    ) -> (
        SymmetricCommitmentKey<E>,
        VerificationKey<E>,
        ThresholdKeys<E>,
    ) {
        keygen(threshold, num_signers, num_attributes, rng)
    }

    /// doesn't feel like a protocol thing because a user does this by themself?
    /// User creates a credential request
    /// # Returns
    /// * A new credential with commitments to attributes
    pub fn request_credential<E: Pairing>(
        commitment_key: SymmetricCommitmentKey<E>,
        attributes: Option<&[E::ScalarField]>,
        rng: &mut impl Rng,
    ) -> Result<(Credential<E>, CredentialCommitments<E>), CredentialError> {
        let mut credential = Credential::new(commitment_key, attributes, rng);
        let commitments = credential.compute_commitments_per_m(rng)?;
        Ok((credential, commitments))
    }

    /// Issuer signs a credential request
    /// # Returns
    /// * A partial signature from this signer
    pub fn issue_share<E: Pairing>(
        signer: &Signer<E>,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        h: &E::G1Affine,
    ) -> Result<PartialSignature<E>, SignatureError> {
        signer.sign_share(commitments, commitment_proofs, h)
    }

    /// User collects signatures from multiple issuers
    pub fn collect_signature_shares<E: Pairing>(
        signers: &[Signer<E>],
        credential_request: &CredentialCommitments<E>,
        threshold: usize,
    ) -> Result<Vec<(usize, PartialSignature<E>)>, SignatureError> {
        let mut shares = Vec::new();

        // Request signatures from enough signers
        for signer in signers.iter().take(threshold + 1) {
            let sig_share = signer.sign_share(
                &credential_request.commitments,
                &credential_request.proofs,
                &credential_request.h,
            )?;

            shares.push((sig_share.party_index, sig_share));

            if shares.len() >= threshold + 1 {
                break;
            }
        }

        // Check if we have enough shares
        if shares.len() < threshold + 1 {
            return Err(SignatureError::InsufficientShares {
                needed: threshold + 1,
                got: shares.len(),
            });
        }

        Ok(shares)
    }

    /// User verifies signature shares before aggregation (implements RS.ShareVer)
    pub fn verify_signature_shares<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        vk_shares: &[VerificationKeyShare<E>],
        credential_request: &CredentialCommitments<E>,
        signature_shares: &[(usize, PartialSignature<E>)],
        threshold: usize,
    ) -> Result<Vec<(usize, PartialSignature<E>)>, VerificationError> {
        // Use the UserVerification module to verify shares
        User::process_signature_shares(
            commitment_key,
            vk_shares,
            &credential_request.commitments,
            &credential_request.proofs,
            signature_shares,
            threshold,
        )
    }

    /// Aggregate signature shares into a complete threshold signature
    /// run by a user to combine all the signature shares
    /// # Returns
    /// * A complete threshold signature
    pub fn aggregate_shares<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        shares: &[(usize, PartialSignature<E>)],
        blindings: &[E::ScalarField],
        threshold: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, SignatureError> {
        ThresholdSignature::aggregate_signature_shares(
            commitment_key,
            shares,
            blindings,
            threshold,
            h,
        )
    }

    /// User shows credential without revealing attributes
    /// # Returns
    /// * A ZKP presentation of the credential
    pub fn show<E: Pairing>(
        credential: &Credential<E>,
        rng: &mut impl Rng,
    ) -> Result<(ThresholdSignature<E>, E::G1Affine, E::G2Affine, Vec<u8>), CredentialError> {
        credential.show(rng)
    }

    /// Verify a credential presentation
    /// # Returns
    /// * Whether the credential is valid
    pub fn verify<E: Pairing>(
        commitment_key: &SymmetricCommitmentKey<E>,
        verification_key: &VerificationKey<E>,
        commitment: &E::G1Affine,
        commitment_tilde: &E::G2Affine,
        signature: &ThresholdSignature<E>,
        proof: &Vec<u8>,
    ) -> Result<bool, VerificationError> {
        Verifier::<E>::verify(
            commitment_key,
            verification_key,
            commitment,
            commitment_tilde,
            signature,
            proof,
        )
    }
}
