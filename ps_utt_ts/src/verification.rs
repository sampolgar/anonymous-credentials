use crate::keygen::VerificationKeyShare;
use crate::signature::{PartialSignature, ThresholdSignature, ThresholdSignatureError};
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::ops::{Mul, Neg};
use std::marker::PhantomData;
use utils::pairing::PairingCheck;

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

        // Calculate lhs side of the equation e(-sigma_i, g̃)
        let sigma_i = &sig_share.sigma.into_group().neg();
        pairs.push((sigma_i, &E::G2Prepared::from(ck.g_tilde)));

        // add e(h, g̃^[x]_i)

        // Add e(h, g̃^[x]_i)
        let g_tilde_x_share = vk_share.g_tilde_x_share;
        pairs.push((
            &sig_share.h.into_group(),
            &E::G2Prepared::from(g_tilde_x_share),
        ));

        // Add ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        for (k, commitment) in commitments.iter().enumerate() {
            if k < vk_share.g_tilde_y_shares.len() {
                pairs.push((
                    &commitment.into_group(),
                    &E::G2Prepared::from(vk_share.g_tilde_y_shares[k]),
                ));
            }
        }

        // Calculate the left-hand side of the equation
        let sigma_pair = (sigma_i, &E::G2Prepared::from(ck.g_tilde));

        // Verify that e(σ_i,2, g̃) = e(h, g̃^[x]_i) · ∏_{k∈[ℓ]} e(cm_k, g̃^[y_k]_i)
        PairingCheck::<E>::verify_with_negation(&[sigma_pair], &pairs)
    }
}
