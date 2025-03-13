use crate::commitment::{Commitment, CommitmentProof};
use crate::errors::{CommitmentError, SignatureError, VerificationError};
use crate::keygen::{VerificationKey, VerificationKeyShare};
use crate::signature::{PartialSignature, ThresholdSignature};
use crate::symmetric_commitment::SymmetricCommitmentKey;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalDeserialize;
use ark_std::ops::{Add, Mul, Neg};
use thiserror::Error;
use utils::pairing::{verify_pairing_equation, PairingCheck};

pub struct Verifier<E: Pairing> {
    vk: VerificationKey<E>,
    ck: SymmetricCommitmentKey<E>,
}

impl<E: Pairing> Verifier<E> {
    pub fn new(vk: VerificationKey<E>, ck: SymmetricCommitmentKey<E>) -> Self {
        Self { vk, ck }
    }

    /// Verify a threshold signature using commitments
    /// Following RS.Ver from the protocol
    pub fn verify(
        ck: &SymmetricCommitmentKey<E>,
        vk: &VerificationKey<E>,
        cm: &E::G1Affine,
        cm_tilde: &E::G2Affine,
        sig: &ThresholdSignature<E>,
        serialized_proof: &[u8],
    ) -> Result<bool, VerificationError> {
        let p1 = E::pairing(sig.sigma, ck.g_tilde);
        let p2 = E::pairing(sig.h, vk.g_tilde_x.add(cm_tilde));
        assert_eq!(p1, p2, "first pairing not working");
        // let is_valid = p1 == p2;

        if p1 != p2 {
            return Err(VerificationError::SignatureVerificationFailed);
        }
        // Second pairing check (commitment consistency)
        let p3 = E::pairing(cm, ck.g_tilde);
        let p4 = E::pairing(ck.g, cm_tilde);

        if p3 != p4 {
            return Err(VerificationError::CommitmentConsistencyFailed);
        }

        // Verify the proof
        let is_valid = Commitment::<E>::verify(&serialized_proof)?;
        Ok(is_valid)
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
}
