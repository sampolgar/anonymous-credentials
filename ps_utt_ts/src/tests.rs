use crate::{
    commitment::Commitment,
    credential::Credential,
    credential::CredentialCommitments,
    errors::VerificationError,
    keygen::{SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare},
    protocol::Protocol,
    shamir::reconstruct_secret,
    signature::{PartialSignature, ThresholdSignature},
    signer::Signer,
    symmetric_commitment::SymmetricCommitmentKey,
    verifier::Verifier,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::ops::{Add, Mul, Neg};

// Constants for tests
const THRESHOLD: usize = 2;
const N_PARTICIPANTS: usize = 5;
const L_ATTRIBUTES: usize = 3;

#[cfg(test)]
mod tests {
    use crate::symmetric_commitment;

    use super::*;

    #[test]
    fn test_keygen() {
        let mut rng = test_rng();

        // Generate keys
        let (ck, vk, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            THRESHOLD,
            N_PARTICIPANTS,
            L_ATTRIBUTES,
            &mut rng,
        );

        // Verify correct number of shares
        assert_eq!(ts_keys.sk_shares.len(), N_PARTICIPANTS);
        assert_eq!(ts_keys.vk_shares.len(), N_PARTICIPANTS);

        // Verify each share has correct attributes
        for i in 0..N_PARTICIPANTS {
            assert_eq!(ts_keys.sk_shares[i].y_shares.len(), L_ATTRIBUTES);
            assert_eq!(ts_keys.vk_shares[i].g_tilde_y_shares.len(), L_ATTRIBUTES);
        }

        // Test secret reconstruction
        let subset_indices = (0..THRESHOLD + 1).collect::<Vec<_>>();

        // Collect x shares from these participants
        let x_shares_subset: Vec<(usize, Fr)> = subset_indices
            .iter()
            .map(|&i| (ts_keys.sk_shares[i].index, ts_keys.sk_shares[i].x_share))
            .collect();

        // Reconstruct x
        let reconstructed_x = reconstruct_secret(&x_shares_subset, THRESHOLD + 1);

        // Verify that g_tilde^reconstructed_x equals vk.g_tilde_x
        let computed_g_tilde_x = ck.g_tilde.mul(reconstructed_x).into_affine();
        assert_eq!(
            computed_g_tilde_x, vk.g_tilde_x,
            "Secret reconstruction failed"
        );
    }

    #[test]
    fn test_credential_creation() {
        let mut rng = test_rng();

        // Generate keys
        let (ck, _, _) = Protocol::run_distributed_key_generation::<Bls12_381>(
            THRESHOLD,
            N_PARTICIPANTS,
            L_ATTRIBUTES,
            &mut rng,
        );

        // Create a credential with random attributes
        let messages: Vec<Fr> = (0..L_ATTRIBUTES).map(|_| Fr::rand(&mut rng)).collect();
        let credential = Credential::new(ck, Some(&messages), &mut rng);

        // Verify the credential has the correct messages
        let stored_messages = credential.get_messages();
        assert_eq!(stored_messages.len(), L_ATTRIBUTES);

        for i in 0..L_ATTRIBUTES {
            assert_eq!(stored_messages[i], messages[i]);
        }
    }

    #[test]
    fn test_signature_shares() {
        let mut rng = test_rng();

        // Generate keys
        let (ck, _, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            THRESHOLD,
            N_PARTICIPANTS,
            L_ATTRIBUTES,
            &mut rng,
        );

        // Create signers
        let signers: Vec<_> = ts_keys
            .sk_shares
            .iter()
            .zip(ts_keys.vk_shares.iter())
            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
            .collect();

        // Create a credential with random attributes
        let messages: Vec<Fr> = (0..L_ATTRIBUTES).map(|_| Fr::rand(&mut rng)).collect();
        let mut credential = Credential::new(ck.clone(), Some(&messages), &mut rng);

        // Generate commitments
        let commitments = credential
            .compute_commitments_per_m(&mut rng)
            .expect("Failed to compute commitments");

        // Have each signer generate a signature share
        let mut signature_shares = Vec::new();

        for (i, signer) in signers.iter().enumerate() {
            let sig_share = signer
                .sign_share(
                    &commitments.commitments,
                    &commitments.proofs,
                    &commitments.h,
                )
                .expect(&format!("Signer {} failed to generate signature share", i));

            signature_shares.push((sig_share.party_index, sig_share));
        }

        // Verify we got the right number of shares
        assert_eq!(
            signature_shares.len(),
            signers.len(),
            "Not all signers produced shares"
        );

        // Verify each signature share
        for (i, (_, share)) in signature_shares.iter().enumerate() {
            let valid = ThresholdSignature::<Bls12_381>::verify_share(
                &ck,
                &ts_keys.vk_shares[i],
                &commitments.commitments,
                share,
            );

            assert!(valid, "Signature share {} is invalid", i);
        }
    }

    #[test]
    fn test_signature_aggregation() {
        let mut rng = test_rng();

        // Generate keys
        let (ck, vk, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            THRESHOLD,
            N_PARTICIPANTS,
            L_ATTRIBUTES,
            &mut rng,
        );

        // Create signers
        let signers: Vec<_> = ts_keys
            .sk_shares
            .iter()
            .zip(ts_keys.vk_shares.iter())
            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
            .collect();

        // Create a credential with random attributes
        let messages: Vec<Fr> = (0..L_ATTRIBUTES).map(|_| Fr::rand(&mut rng)).collect();
        let mut credential = Credential::new(ck.clone(), Some(&messages), &mut rng);

        // Generate commitments
        let commitments = credential
            .compute_commitments_per_m(&mut rng)
            .expect("Failed to compute commitments");

        // Have each signer generate a signature share
        let mut signature_shares = Vec::new();

        for (i, signer) in signers.iter().enumerate() {
            let sig_share = signer
                .sign_share(
                    &commitments.commitments,
                    &commitments.proofs,
                    &commitments.h,
                )
                .expect(&format!("Signer {} failed to generate signature share", i));

            signature_shares.push((sig_share.party_index, sig_share));
        }

        // Get the blinding factors used in the commitments
        let blindings = credential.get_blinding_factors();

        // We only need threshold+1 shares for aggregation
        let sufficient_shares = signature_shares
            .iter()
            .take(THRESHOLD + 1)
            .map(|(idx, share)| (*idx, share.clone()))
            .collect::<Vec<_>>();

        // Aggregate the signature shares
        let threshold_signature = Protocol::aggregate::<Bls12_381>(
            &ck,
            &sufficient_shares,
            &blindings,
            THRESHOLD,
            &commitments.h,
        )
        .expect("Failed to aggregate signature shares");

        // Verify the aggregated signature
        let valid =
            Verifier::<Bls12_381>::verify_signature(&ck, &vk, &messages, &threshold_signature);

        assert!(valid, "Aggregated signature verification failed");
    }

    #[test]
    fn test_signature_rerandomization() {
        let mut rng = test_rng();

        // Generate keys
        let (ck, vk, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            THRESHOLD,
            N_PARTICIPANTS,
            L_ATTRIBUTES,
            &mut rng,
        );

        // Create signers
        let signers: Vec<_> = ts_keys
            .sk_shares
            .iter()
            .zip(ts_keys.vk_shares.iter())
            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
            .collect();

        // Create a credential with random attributes
        let messages: Vec<Fr> = (0..L_ATTRIBUTES).map(|_| Fr::rand(&mut rng)).collect();
        let mut credential = Credential::new(ck.clone(), Some(&messages), &mut rng);

        // Generate commitments
        let commitments = credential
            .compute_commitments_per_m(&mut rng)
            .expect("Failed to compute commitments");

        // Get signature shares
        let mut signature_shares = Vec::new();
        for signer in signers.iter().take(THRESHOLD + 1) {
            let sig_share = signer
                .sign_share(
                    &commitments.commitments,
                    &commitments.proofs,
                    &commitments.h,
                )
                .expect("Failed to generate signature share");

            signature_shares.push((sig_share.party_index, sig_share));
        }

        // Aggregate signatures
        let blindings = credential.get_blinding_factors();
        let threshold_signature = Protocol::aggregate::<Bls12_381>(
            &ck,
            &signature_shares,
            &blindings,
            THRESHOLD,
            &commitments.h,
        )
        .expect("Failed to aggregate signature shares");

        // Attach the signature to the credential
        credential.attach_signature(threshold_signature.clone());

        // Verify original signature
        let valid_original =
            Verifier::<Bls12_381>::verify_signature(&ck, &vk, &messages, &threshold_signature);
        assert!(valid_original, "Original signature verification failed");

        // Rerandomize signature
        let (rand_sig, cm, cm_tilde, proof) = credential
            .show(&mut rng)
            .expect("Failed to generate credential presentation");

        // Verify the blind signature
        let verification_result: Result<bool, VerificationError> =
            Verifier::verify(&ck, &vk, &cm, &cm_tilde, &rand_sig, &proof);

        match verification_result {
            Ok(valid) => {
                assert!(valid, "Blind signature verification failed");
                println!("✅ Blind signature verification passed");
            }
            Err(err) => {
                panic!("Blind signature verification error: {:?}", err);
            }
        }
    }
}
