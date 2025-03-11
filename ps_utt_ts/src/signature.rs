// includes threshold_signature operations
//
use crate::commitment::{Commitment, CommitmentError};
use crate::keygen::{keygen, SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare};
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
use thiserror::Error;
use utils::pairing::PairingCheck;

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

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct RerandomizedThresholdSignature<E: Pairing> {
    pub h_prime: E::G1Affine,
    pub sigma_prime: E::G1Affine,
}

#[derive(Debug)]
pub enum ThresholdSignatureError {
    SerializationError(SerializationError),
    CommitmentError(CommitmentError),
    InvalidShare(usize),
    DuplicateShare(usize),
    ThresholdNotMet,
    InsufficientShares { needed: usize, got: usize },
}

impl From<CommitmentError> for ThresholdSignatureError {
    fn from(err: CommitmentError) -> Self {
        ThresholdSignatureError::CommitmentError(err)
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
// /// Verify a threshold signature against a message and verification key
// pub fn verify_signature<E: Pairing>(
//     ck: &SymmetricCommitmentKey<E>,
//     vk: &VerificationKey<E>,
//     cm: &E::G1Affine,
//     cm_tilde: &E::G2Affine,
//     sig: &RerandomizedThresholdSignature<E>,
// ) -> bool {
//     let mut rng = ark_std::test_rng();
//     let mr = std::sync::Mutex::new(rng);

//     // Optimized check: e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
//     let vk_plus_cm_tilde = vk.g_tilde_x.add(cm_tilde).into_affine();
//     let check1 = PairingCheck::<E>::rand(
//         &mr,
//         &[
//             (&sig.sigma_prime, &ck.g_tilde),
//             (
//                 &sig.h_prime.into_group().neg().into_affine(),
//                 &vk_plus_cm_tilde,
//             ),
//         ],
//         &E::TargetField::one(),
//     );

//     // Optimized check: e(cmg1, g2) * e(g1, cmg2)^-1 = 1
//     let check2 = PairingCheck::<E>::rand(
//         &mr,
//         &[
//             (&cm, &ck.g_tilde),
//             (&ck.g.into_group().neg().into_affine(), &cm_tilde),
//         ],
//         &E::TargetField::one(),
//     );

//     let mut final_check = PairingCheck::<E>::new();
//     final_check.merge(&check1);
//     final_check.merge(&check2);
//     final_check.verify()
// }

// //TODO update to include randomizers within the function, returning randomized sig and u_delta?
// // or create a function that randomizes the signature and commitment together
// pub fn rerandomize<E: Pairing>(
//     sig: &ThresholdSignature<E>,
//     r_delta: &E::ScalarField,
//     u_delta: &E::ScalarField,
// ) -> RerandomizedThresholdSignature<E> {
//     let h_prime = sig.h.mul(u_delta);
//     let r_times_u = r_delta.mul(u_delta);

//     let scalars = vec![r_times_u, *u_delta];
//     let points = vec![sig.h, sig.sigma];
//     let sigma_prime = E::G1::msm_unchecked(&points, &scalars);

//     let proj_points = vec![h_prime, sigma_prime];
//     let affine_points = E::G1::normalize_batch(&proj_points);

//     RerandomizedThresholdSignature {
//         h_prime: affine_points[0],
//         sigma_prime: affine_points[1],
//     }

//     // previously was this:
//     // let sigma1_prime = self.sigma1.mul(u_delta).into_affine();
//     // let temp = self.sigma1.mul(r_delta);
//     // let sigma2_prime = (temp.add(self.sigma2)).mul(u_delta).into_affine();
//     // Self {
//     //     sigma1: sigma1_prime,
//     //     sigma2: sigma2_prime,
//     // }
// }

/// Aggregate signature shares into a complete threshold signature
pub fn aggregate_signature_shares<E: Pairing>(
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
