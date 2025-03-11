use crate::commitment::CommitmentError;
use crate::credential::{Credential, CredentialCommitments};
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::signature::{
    aggregate_signature_shares, PartialSignature, ThresholdSignature, ThresholdSignatureError,
};
use crate::signer::Signer;
// use crate::signer::Signer;
use crate::keygen::VerificationKeyShare;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use crate::verification::Verifier;
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

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
        threshold: usize,
    ) -> Result<(Vec<(usize, PartialSignature<E>)>, E::G1Affine), ThresholdSignatureError> {
        // Implementation as before...
    }

    pub fn share_sign<E: Pairing>(
        signer: &Signer<E>,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        h: &E::G1Affine,
    ) -> Result<PartialSignature<E>, ThresholdSignatureError> {
        signer.sign_share(&commitments, &commitment_proofs, &h)
    }

    pub fn share_verify<E: Pairing>(
        ck: &SymmetricCommitmentKey<E>,
        vk_share: &VerificationKeyShare<E>,
        commitments: &[E::G1Affine],
        sig_share: &PartialSignature<E>,
    ) -> bool {
        Verifier::<E>::verify_share(ck, vk_share, commitments, sig_share)
    }

    pub fn aggregate<E: Pairing>(
        ck: &SymmetricCommitmentKey<E>,
        shares: &[(usize, PartialSignature<E>)],
        t: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, ThresholdSignatureError> {
        aggregate_signature_shares(ck, shares, t, h)
    }
}
