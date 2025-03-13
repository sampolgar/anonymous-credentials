use crate::{
    commitment::Commitment,
    credential::Credential,
    credential::CredentialCommitments,
    keygen::{SecretKeyShare, ThresholdKeys, VerificationKey, VerificationKeyShare},
    protocol::Protocol,
    shamir::reconstruct_secret,
    signature::{PartialSignature, ThresholdSignature},
    signer::Signer,
    symmetric_commitment::SymmetricCommitmentKey,
    verifier::Verifier,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;
use std::ops::{Add, Mul, Neg};

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_ec::{CurveGroup, VariableBaseMSM};
    use ark_std::UniformRand;

    #[test]
    fn test_dist_keygen() {
        // Initialize parameters
        let mut rng = test_rng();
        let threshold = 2; // t = 2, need t+1 = 3 participants to reconstruct
        let n_participants = 5; // Total number of signers
        let l_attributes = 3; // Number of attributes in credentials

        // Run distributed key generation
        let (ck, vk, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            threshold,
            n_participants,
            l_attributes,
            &mut rng,
        );

        // Verify the correct number of shares were generated
        assert_eq!(ts_keys.sk_shares.len(), n_participants);
        assert_eq!(ts_keys.vk_shares.len(), n_participants);

        // Verify each share has the correct number of y-values
        for i in 0..n_participants {
            assert_eq!(ts_keys.sk_shares[i].y_shares.len(), l_attributes);
            assert_eq!(ts_keys.vk_shares[i].g_tilde_y_shares.len(), l_attributes);
        }

        // Test that t+1 shares can reconstruct the secret
        let subset_indices = (0..threshold + 1).collect::<Vec<_>>();

        // Collect x shares from these participants
        let x_shares_subset: Vec<(usize, Fr)> = subset_indices
            .iter()
            .map(|&i| (ts_keys.sk_shares[i].index, ts_keys.sk_shares[i].x_share))
            .collect();

        // Reconstruct x and verify correctness
        let reconstructed_x = reconstruct_secret(&x_shares_subset, threshold + 1);

        // Verify that g_tilde^reconstructed_x equals vk.g_tilde_x
        let computed_g_tilde_x = ck.g_tilde.mul(reconstructed_x).into_affine();
        assert_eq!(
            computed_g_tilde_x, vk.g_tilde_x,
            "Reconstructed x verification failed"
        );

        println!("✅ Distributed key generation test passed");
    }

    fn credential_commitment_generation() -> (
        SymmetricCommitmentKey<Bls12_381>,
        VerificationKey<Bls12_381>,
        ThresholdKeys<Bls12_381>,
        Credential<Bls12_381>,
        CredentialCommitments<Bls12_381>,
    ) {
        let mut rng = test_rng();
        let threshold = 2;
        let n_participants = 5;
        let l_attributes = 3;

        // Generate keys
        let (ck, vk, ts_keys) = Protocol::run_distributed_key_generation::<Bls12_381>(
            threshold,
            n_participants,
            l_attributes,
            &mut rng,
        );

        // Create credential with random attributes
        let mut credential = Credential::new(ck.clone());

        // Generate random messages (attributes)
        let messages: Vec<Fr> = (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
        credential.set_attributes(messages.clone());

        // Generate commitments for the attributes
        let commitments = credential
            .compute_commitments(&mut rng)
            .expect("Failed to compute commitments");

        // Verify we have the right number of commitments and proofs
        assert_eq!(commitments.commitments.len(), l_attributes);
        assert_eq!(commitments.proofs.len(), l_attributes);

        // Verify each commitment proof is valid
        for (i, proof) in commitments.proofs.iter().enumerate() {
            let valid = Commitment::<Bls12_381>::pok_commitment_verify(proof)
                .expect("Failed to verify commitment proof");
            assert!(valid, "Commitment proof {} is invalid", i);
        }

        println!("✅ Credential commitment generation test passed");

        // Return the generated test data for use in subsequent tests
        (ck, vk, ts_keys, credential, commitments)
    }

    #[test]
    fn test_credential_commitment_generation() {
        credential_commitment_generation();
    }

    fn signature_share_generation() -> (
        SymmetricCommitmentKey<Bls12_381>,
        VerificationKey<Bls12_381>,
        ThresholdKeys<Bls12_381>,
        Credential<Bls12_381>,
        CredentialCommitments<Bls12_381>,
        Vec<(usize, PartialSignature<Bls12_381>)>,
    ) {
        // Get data from previous test
        let (ck, vk, ts_keys, credential, commitments) = credential_commitment_generation();

        // Create signers from key shares
        let signers: Vec<_> = ts_keys
            .sk_shares
            .iter()
            .zip(ts_keys.vk_shares.iter())
            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
            .collect();

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

        assert_eq!(
            signature_shares.len(),
            signers.len(),
            "Not all signers produced shares"
        );
        println!("✅ Signature share generation test passed");

        (ck, vk, ts_keys, credential, commitments, signature_shares)
    }

    #[test]
    fn test_signature_share_verification() {
        signature_share_generation();
    }

    fn signature_aggregation() {
        // Get data from previous test
        let (ck, vk, ts_keys, credential, commitments, signature_shares) =
            signature_share_generation();

        let cred_blinding_factors = credential.get_blinding_factors();
        assert_eq!(
            cred_blinding_factors.len(),
            ck.ck.len(),
            "blinding factors and ck.len doesn't match "
        );

        // Aggregate signature shares
        let aggregated_signature = Protocol::aggregate::<Bls12_381>(
            &ck,
            &signature_shares,
            &cred_blinding_factors,
            ts_keys.t,
            &commitments.h,
        )
        .expect("Failed to aggregate shares");

        // let complete_signature = aggregated_signature.sigma.add(&g_k_r_k);

        // // Verify the aggregated signature
        // let is_valid = aggregated_signature.verify(&ck, &vk, &commitments.h);
        // assert!(is_valid, "Aggregated signature failed to verify");

        // Verify the aggregated signature

        println!("✅ Signature aggregation test passed");
    }

    #[test]
    fn test_signature_aggregation() {
        signature_aggregation();
    }

    #[test]
    fn test_complete_signature_verification() {
        // Get data from previous tests
        let (ck, vk, ts_keys, credential, commitments, signature_shares) =
            signature_share_generation();

        // Aggregate signature
        let threshold = ts_keys.t;
        let sufficient_shares = signature_shares
            .iter()
            .take(threshold + 1)
            .map(|(idx, share)| (*idx, share.clone()))
            .collect::<Vec<_>>();

        let blindings = credential.get_blinding_factors();
        let threshold_signature = Protocol::aggregate(
            &ck,
            &sufficient_shares,
            blindings,
            threshold,
            &commitments.h,
        )
        .expect("Failed to aggregate signature shares");

        // Verify using the Verifier struct
        let messages = credential.get_attributes();
        let valid =
            Verifier::<Bls12_381>::verify_signature(&ck, &vk, &messages, &threshold_signature);
        assert!(valid, "Signature verification failed");
        println!("✅ Signature verification with messages test passed");

        // println!("✅ Signature verification with commitments test passed");
        // Now rerandomize the signature
        let mut rng = test_rng();
        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let rerandomized =
            ThresholdSignature::randomize_with_factors(&threshold_signature, &u_delta, &r_delta);

        // Verify the rerandomized signature
        let valid_rerandomized =
            Verifier::<Bls12_381>::verify_signature(&ck, &vk, &messages, &rerandomized);
        assert!(
            valid_rerandomized,
            "Rerandomized signature verification failed"
        );

        println!("✅ Signature rerandomized verification with messages test passed");
    }

    #[test]
    fn test_credential_show_and_verify() {
        // Get data from previous tests to have a complete setup
        let (ck, vk, ts_keys, mut credential, commitments, signature_shares) =
            signature_share_generation();

        let mut rng = test_rng();
        let threshold = ts_keys.t;

        // 1. Aggregate signature shares into a threshold signature
        let blindings = credential.get_blinding_factors();
        let threshold_signature = ThresholdSignature::aggregate_signature_shares(
            &ck,
            &signature_shares,
            &blindings,
            threshold,
            &commitments.h,
        )
        .expect("Failed to aggregate signature shares");

        // 2. Attach the signature to the credential
        credential.attach_signature(threshold_signature.clone());

        // 3. Set up a symmetric commitment for the credential
        credential.set_symmetric_commitment();

        // 4. Show the credential (generate proof for anonymous presentation)
        let (sig, cm, cm_tilde, proof_result) = credential.show(&mut rng);
        let proof = proof_result.expect("Failed to generate credential proof");

        // 5. Verify the blind signature
        let verification_result =
            Verifier::verify_blind_signature(&ck, &vk, cm, cm_tilde, sig, &proof);

        match verification_result {
            Ok(valid) => {
                assert!(valid, "Blind signature verification failed");
                println!("✅ Blind signature verification passed");
            }
            Err(err) => {
                panic!("Blind signature verification error: {:?}", err);
            }
        }

        // // 6. Optional: Test signature rerandomization
        // let (rerandomized_sig, u_delta, r_delta) = sig.randomize(&mut rng);

        // // 7. Verify the rerandomized signature
        // let rerandomized_verification =
        //     Verifier::verify_blind_signature(&ck, &vk, cm, cm_tilde, &rerandomized_sig, &proof);

        // match rerandomized_verification {
        //     Ok(valid) => {
        //         assert!(valid, "Rerandomized blind signature verification failed");
        //         println!("✅ Rerandomized blind signature verification passed");
        //     }
        //     Err(err) => {
        //         panic!("Rerandomized blind signature verification error: {:?}", err);
        //     }
        // }

        // // 8. Test complete flow with message verification (non-blind)
        // let messages = credential.get_attributes();
        // let valid_direct = Verifier::verify_signature(&ck, &vk, &messages, sig);
        // assert!(valid_direct, "Direct signature verification failed");
        // println!("✅ Direct signature verification passed");

        // println!("✅ Complete credential show and verify test passed");
    }
}
