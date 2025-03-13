use crate::commitment::{Commitment, CommitmentError};
use crate::keygen::{keygen, SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare};
use crate::proofs::{CommitmentProofs, ProofError};
use crate::symmetric_commitment::{SymmetricCommitment, SymmetricCommitmentKey};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use utils::pairing::{verify_pairing_equation, PairingCheck};

#[derive(Debug)]
pub enum ThresholdSignatureError {
    SerializationError(SerializationError),
    CommitmentError(CommitmentError),
    InvalidShare(usize),
    DuplicateShare(usize),
    ThresholdNotMet,
    InsufficientShares { needed: usize, got: usize },
    ProofError(ProofError),
}

impl From<ProofError> for ThresholdSignatureError {
    fn from(error: ProofError) -> Self {
        ThresholdSignatureError::ProofError(error)
    }
}

impl From<CommitmentError> for ThresholdSignatureError {
    fn from(err: CommitmentError) -> Self {
        ThresholdSignatureError::CommitmentError(err)
    }
}

#[derive(Clone, Debug)]
pub struct PartialSignature<E: Pairing> {
    pub party_index: usize,
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ThresholdSignature<E: Pairing> {
    pub h: E::G1Affine,
    pub sigma: E::G1Affine,
}

impl<E: Pairing> ThresholdSignature<E> {
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
    /// Aggregate signature shares into a complete threshold signature
    /// A user would do this
    pub fn aggregate_signature_shares(
        ck: &SymmetricCommitmentKey<E>,
        signature_shares: &[(usize, PartialSignature<E>)],
        blindings: &[E::ScalarField],
        threshold: usize,
        h: &E::G1Affine,
    ) -> Result<ThresholdSignature<E>, ThresholdSignatureError> {
        // Check that we have enough signature shares
        if signature_shares.len() < threshold + 1 {
            return Err(ThresholdSignatureError::InsufficientShares {
                needed: threshold + 1,
                got: signature_shares.len(),
            });
        }

        // Extract indices and signature components
        let mut indices = Vec::with_capacity(signature_shares.len());
        let mut sigma_2_components = Vec::with_capacity(signature_shares.len());

        for (_, share) in signature_shares {
            indices.push(share.party_index);
            sigma_2_components.push((share.party_index, share.sigma));
        }

        // Compute Lagrange coefficients for each party
        let mut sigma_2 = E::G1::zero();

        for (idx, (i, sigma_i_2)) in sigma_2_components.iter().enumerate().take(threshold + 1) {
            // Compute Lagrange coefficient for party i
            let lagrange_i = compute_lagrange_coefficient::<E::ScalarField>(&indices, *i);

            // Add contribution: sigma_i,2^{L_i}
            sigma_2 = sigma_2 + sigma_i_2.mul(lagrange_i);
        }

        let g_k_r_k = E::G1::msm_unchecked(&ck.ck, blindings).neg();

        let final_sigma = (sigma_2 + g_k_r_k).into_affine();

        // Construct the final signature
        Ok(ThresholdSignature {
            h: *h,
            sigma: final_sigma,
        })
    }

    pub fn randomize(&self, rng: &mut impl Rng) -> (ThresholdSignature<E>, E::ScalarField) {
        let u_delta = E::ScalarField::rand(rng);
        let r_delta: <E as Pairing>::ScalarField = E::ScalarField::rand(rng);
        (self.randomize_with_factors(&u_delta, &r_delta), r_delta)
    }

    /// u_delta randomizes sigma1 (h)
    pub fn randomize_with_factors(
        &self,
        u_delta: &E::ScalarField,
        r_delta: &E::ScalarField,
    ) -> ThresholdSignature<E> {
        let h_prime = self.h.mul(u_delta).into_affine();

        // let r_times_u = u_delta.mul(r_delta);
        // let scalars = vec![r_times_u, *u_delta];
        // let points = vec![self.h, self.sigma];
        let temp = self.h.mul(r_delta);
        let sigma_prime = (temp + self.sigma).mul(u_delta).into_affine();

        ThresholdSignature {
            h: h_prime,
            sigma: sigma_prime,
        }
    }
}

pub fn compute_lagrange_coefficient<F: Field>(indices: &[usize], j: usize) -> F {
    let j_field = F::from(j as u64);

    let mut result = F::one();
    for &i in indices {
        if i == j {
            continue;
        }

        let i_field = F::from(i as u64);
        let numerator = i_field;
        let denominator = j_field - i_field;

        // Compute i/(j-i)
        result *= numerator * denominator.inverse().expect("indices should be distinct");
    }

    result
}
