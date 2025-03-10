// protocol.rs
use crate::commitment::CommitmentError;
use crate::credential::{Credential, CredentialCommitments};
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
// use crate::signature::{BlindSignature, SignatureShare, ThresholdSignatureError};
// use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

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

// /// Generate credential commitments for attributes
// pub fn create_credential_commitments<E: Pairing>(
//     ck: &SymmetricCommitmentKey<E>,
//     messages: &[E::ScalarField],
//     rng: &mut impl Rng,
// ) -> Result<CredentialCommitments<E>, CommitmentError> {
// }
