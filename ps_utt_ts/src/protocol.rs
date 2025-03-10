// protocol.rs
use crate::commitment::CommitmentError;
use crate::credential::{Credential, CredentialCommitments};
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::params::PublicParams;
// use crate::signature::{BlindSignature, SignatureShare, ThresholdSignatureError};
use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

/// Runs the distributed key generation protocol
pub fn run_distributed_key_generation<E: Pairing>(
    params: &PublicParams<E>,
    threshold: usize,
    num_signers: usize,
    num_attributes: usize,
    rng: &mut impl Rng,
) -> (
    SymmetricCommitmentKey<E>,
    VerificationKey<E>,
    ThresholdKeys<E>,
) {
    keygen(params, threshold, num_signers, num_attributes, rng)
}

/// Generate credential commitments for attributes
pub fn create_credential_commitments<E: Pairing>(
    params: &PublicParams<E>,
    ck: &SymmetricCommitmentKey<E>,
    messages: &[E::ScalarField],
    rng: &mut impl Rng,
) -> Result<CredentialCommitments<E>, CommitmentError> {
    let mut credential = Credential::new(params.clone(), ck.clone());
    credential.set_attributes(messages.to_vec());
    credential.compute_commitments(rng)
}
