use crate::keygen::VerificationKeyShare;
use crate::signature::{PartialSignature, ThresholdSignature, ThresholdSignatureError};
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::ops::{Mul, Neg};
use std::marker::PhantomData;
use utils::pairing::{verify_pairing_equation, PairingCheck};

pub struct Verifier<E: Pairing> {
    _marker: PhantomData<E>,
}

impl<E: Pairing> Verifier<E> {
    /// Verify a signature share from a specific signer
    /// Following RS.ShareVer from the protocol
    pub fn verify_share(
        ck: &SymmetricCommitmentKey<E>,
        vk_share: &VerificationKeyShare<E>,
        commitments: &[E::G1Affine],
        sig_share: &PartialSignature<E>,
    ) -> bool {
        // Verify pairing equation:
        // e(σ_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        // change to
        // e(-sigma_i, tilde_g) . e(h, g̃^[x]_i) . ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)

        let mut pairs = Vec::new();

        // e(-sigma_i, g̃) = lhs
        let neg_sigma_i = sig_share.sigma.into_group().neg().into_affine();
        pairs.push((&neg_sigma_i, &ck.g_tilde));

        // Add e(h, g̃^[x]_i)
        let g_tilde_x_share = vk_share.g_tilde_x_share;
        pairs.push((&sig_share.h, &g_tilde_x_share));

        // Add ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        for (k, commitment) in commitments.iter().enumerate() {
            if k < vk_share.g_tilde_y_shares.len() {
                pairs.push((commitment, &vk_share.g_tilde_y_shares[k]));
            }
        }

        // Verify that e(σ_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        verify_pairing_equation::<E>(&pairs, None)
    }
}
