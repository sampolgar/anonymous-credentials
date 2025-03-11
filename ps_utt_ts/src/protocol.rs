use crate::commitment::CommitmentError;
use crate::credential::{Credential, CredentialCommitments};
use crate::keygen::{keygen, ThresholdKeys, VerificationKey};
use crate::signature::PartialSignature;
use crate::signer::Signer;
// use crate::signer::Signer;
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

pub mod protocol {
    use crate::{
        credential, keygen::VerificationKeyShare, signature::{aggregate_signature_shares, ThresholdSignature, ThresholdSignatureError}, verification::Verifier
    };

    use super::*;

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

    pub fn issue<E: Pairing>(
        credential: &mut Credential<E>,
        signers: 
    )

    // // 2. Share signing
    // pub fn share_sign<E: Pairing>(/* params */
    // ) -> Result<PartialSignature<E>, ThresholdSignatureError> { /* ... */
    // }

    // // 3. Share verification
    // pub fn share_verify<E: Pairing>(/* params */) -> bool { /* ... */
    // }

    // // 4. Signature aggregation
    // pub fn aggregate<E: Pairing>(/* params */
    // ) -> Result<ThresholdSignature<E>, ThresholdSignatureError> { /* ... */
    // }
}

// /// Generate credential commitments for attributes
// pub fn create_credential_commitments<E: Pairing>(
//     ck: &SymmetricCommitmentKey<E>,
//     messages: &[E::ScalarField],
//     rng: &mut impl Rng,
// ) -> Result<CredentialCommitments<E>, CommitmentError> {
// }
