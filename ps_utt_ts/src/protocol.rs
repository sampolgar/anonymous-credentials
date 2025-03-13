use crate::credential::{Credential, CredentialCommitments};
use crate::keygen::VerificationKeyShare;
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::signature::compute_lagrange_coefficient;
use crate::signature::{PartialSignature, ThresholdSignature, ThresholdSignatureError};
use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use crate::verifier::Verifier;
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, UniformRand};
pub struct Protocol;

impl Protocol {
    /// Runs the distributed key generation protocol
    pub fn run_distributed_key_generation<E: Pairing>(
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

    /// Request signatures from signers until threshold is reached
    pub fn request_signatures<E: Pairing>(
        credential_requests: &[CredentialCommitments<E>],
        signers: &[Signer<E>],
        t: usize,
    ) -> Result<(Vec<(usize, PartialSignature<E>)>, E::G1Affine), ThresholdSignatureError> {
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
            return Err(ThresholdSignatureError::InsufficientShares {
                needed: t + 1,
                got: shares.len(),
            });
        }
        Ok((shares, h))
    }

    /// signs 1 share of the threshold signature
    pub fn share_sign<E: Pairing>(
        signer: &Signer<E>,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        h: &E::G1Affine,
    ) -> Result<PartialSignature<E>, ThresholdSignatureError> {
        signer.sign_share(&commitments, &commitment_proofs, &h)
    }

    /// Verify a signature share from a specific signer, run by a user to verify their
    /// share has been signed correctly
    pub fn share_verify<E: Pairing>(
        ck: &SymmetricCommitmentKey<E>,
        vk_share: &VerificationKeyShare<E>,
        commitments: &[E::G1Affine],
        sig_share: &PartialSignature<E>,
    ) -> bool {
        ThresholdSignature::<E>::verify_share(ck, vk_share, commitments, sig_share)
    }

    /// Aggregate signature shares into a complete threshold signature
    /// This is run by a user to combine all the signature shares into a single signature
    pub fn aggregate<E: Pairing>(
        ck: &SymmetricCommitmentKey<E>,
        shares: &[(usize, PartialSignature<E>)],
        blindings: &[E::ScalarField],
        t: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, ThresholdSignatureError> {
        ThresholdSignature::aggregate_signature_shares(ck, shares, blindings, t, h)
    }

    /// Verify a complete threshold signature
    /// Verifier runs this to verify the final signature
    pub fn verify<E: Pairing>(
        ck: &SymmetricCommitmentKey<E>,
        vk: &VerificationKey<E>,
        messages: &[E::ScalarField],
        signature: &ThresholdSignature<E>,
    ) -> bool {
        Verifier::<E>::verify_signature(ck, vk, messages, signature)
    }

    // /// Verify a complete threshold signature with commitments
    // pub fn verify_blind_signature<E: Pairing>(
    //     ck: &SymmetricCommitmentKey<E>,
    //     vk: &VerificationKey<E>,
    //     cm: &E::G1Affine,
    //     cm_tilde: &E::G2Affine,
    //     signature: &ThresholdSignature<E>,
    //     proof: &Vec<u8>,
    // ) -> bool {
    //     Verifier::<E>::verify_blind_signature(ck, vk, cm, cm_tilde, signature, proof)
    // }

    // /// Rerandomize a threshold signature
    // /// This is run by a user to rerandomize the signature
    // pub fn rerandomize<E: Pairing>(
    //     signature: &ThresholdSignature<E>,
    //     rng: &mut impl Rng,
    // ) -> RerandomizedThresholdSignature<E> {
    //     ThresholdSignature::randomize(signature, )
    // }

    // // With explicit randomness
    // pub fn rerandomize_with_factors<E: Pairing>(
    //     signature: &ThresholdSignature<E>,
    //     r1: &E::ScalarField,
    //     r2: &E::ScalarField,
    // ) -> RerandomizedThresholdSignature<E> {
    //     rerandomize_signature(signature, r1, r2)
    // }
}
