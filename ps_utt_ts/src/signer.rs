use crate::commitment::{Commitment, CommitmentError};
use crate::keygen::{SecretKeyShare, VerificationKeyShare};
use crate::signature::{PartialSignature, ThresholdSignatureError};
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_std::ops::Mul;

/// A signer in the threshold signature scheme with lifetime parameters
pub struct Signer<'a, E: Pairing> {
    pub ck: &'a SymmetricCommitmentKey<E>,
    pub sk_share: &'a SecretKeyShare<E>,
    pub vk_share: &'a VerificationKeyShare<E>,
}

impl<'a, E: Pairing> Signer<'a, E> {
    /// Create a new signer with key shares
    pub fn new(
        ck: &'a SymmetricCommitmentKey<E>,
        sk_share: &'a SecretKeyShare<E>,
        vk_share: &'a VerificationKeyShare<E>,
    ) -> Self {
        Self {
            ck,
            sk_share,
            vk_share,
        }
    }

    /// sign a share of the threshold signature
    pub fn sign_share(
        &self,
        commitments: &[E::G1Affine],
        commitment_proofs: &[Vec<u8>],
        h: &E::G1Affine,
    ) -> Result<PartialSignature<E>, ThresholdSignatureError> {
        // Verify all commitment proofs
        for (_, proof) in commitments.iter().zip(commitment_proofs.iter()) {
            let valid = Commitment::<E>::pok_commitment_verify(proof)?;
            if !valid {
                return Err(ThresholdSignatureError::InvalidShare(self.sk_share.index));
            }
        }

        // Extract the index and secret key shares
        let i = self.sk_share.index;
        let x_i = self.sk_share.x_share;

        // Compute the partial signature: σ_i = (h, h^[x]_i · ∏_{k∈[ℓ]} cm_k^[y_k]_i)
        let mut sigma = h.mul(x_i);

        // Add the commitment terms
        for (k, commitment) in commitments.iter().enumerate() {
            if k < self.sk_share.y_shares.len() {
                sigma = sigma + commitment.mul(self.sk_share.y_shares[k]);
            }
        }

        Ok(PartialSignature {
            party_index: i,
            h: h.clone(),
            sigma: sigma.into_affine(),
        })
    }
}
