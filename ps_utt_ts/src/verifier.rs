use crate::keygen::{VerificationKey, VerificationKeyShare};
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

    /// Following RS.Ver from the protocol
    pub fn verify_signature(
        ck: &SymmetricCommitmentKey<E>,
        vk: &VerificationKey<E>,
        messages: &[E::ScalarField],
        signature: &ThresholdSignature<E>,
    ) -> bool {
        if messages.len() > ck.ck_tilde.len() {
            return false; // Too many messages
        }

        let mut pairs = Vec::new();

        // e(-σ₂, g̃)
        let neg_sigma = signature.sigma.into_group().neg().into_affine();
        pairs.push((&neg_sigma, &ck.g_tilde));

        // e(h, g̃^x)
        pairs.push((&signature.h, &vk.g_tilde_x));

        // ∏k∈[ℓ] e(h^mk, g̃^yk)
        // Store all h^mk values so they live long enough
        let h_to_mk_vec: Vec<E::G1Affine> = messages
            .iter()
            .enumerate()
            .filter(|(k, _)| *k < ck.ck_tilde.len())
            .map(|(_, &message)| signature.h.mul(message).into_affine())
            .collect();

        // Add pairs to the pairing check
        for (k, h_to_mk) in h_to_mk_vec.iter().enumerate() {
            if k < ck.ck_tilde.len() {
                pairs.push((h_to_mk, &ck.ck_tilde[k]));
            }
        }

        // Verify the pairing equation
        verify_pairing_equation::<E>(&pairs, None)
    }

    /// Verify a threshold signature using commitments
    pub fn verify_signature_with_commitments(
        ck: &SymmetricCommitmentKey<E>,
        vk: &VerificationKey<E>,
        commitments: &[E::G1Affine],
        signature: &ThresholdSignature<E>,
    ) -> bool {
        let mut pairs = Vec::new();

        // e(-σ₂, g̃)
        let neg_sigma = signature.sigma.into_group().neg().into_affine();
        pairs.push((&neg_sigma, &ck.g_tilde));

        // e(h, g̃^x)
        pairs.push((&signature.h, &vk.g_tilde_x));

        // ∏k∈[ℓ] e(cm_k, g̃^yk)
        for (k, commitment) in commitments.iter().enumerate() {
            if k < ck.ck_tilde.len() {
                pairs.push((commitment, &ck.ck_tilde[k]));
            }
        }

        // Verify the pairing equation
        verify_pairing_equation::<E>(&pairs, None)
    }
}
