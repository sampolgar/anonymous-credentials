use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt_ts::credential::Credential;
use ps_utt_ts::keygen::keygen;
use ps_utt_ts::protocol::{IssuerProtocol, UserProtocol, VerifierProtocol};
use ps_utt_ts::signer::Signer;
use std::time::Duration;

// Constants for benchmarking
const THRESHOLD: usize = 2;
const N_PARTICIPANTS: usize = 5;
const L_ATTRIBUTES: usize = 3;

/// Benchmark function for threshold PS protocol
fn benchmark_threshold_ps(c: &mut Criterion) {
    // Test configurations to match tACT paper's parameters
    let configs = [
        // Basic test case configuration
        (N_PARTICIPANTS, THRESHOLD, L_ATTRIBUTES),
        // N=4, t=N/2+1=3, with varying attribute sizes
        (4, 3, 10),
        // (4, 3, 30),
        // (4, 3, 40),
        // (4, 3, 128),
        // N=64, t=N/2+1=33, with varying attribute sizes
        // (64, 33, 10),
        // (64, 33, 30),
        // (64, 33, 40),
        // (64, 33, 128),
    ];

    // TokenRequest benchmarks
    {
        let mut group = c.benchmark_group("TokenRequest");
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(5));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            group.bench_function(
                BenchmarkId::from_parameter(format!("TokenRequest_{}", id_suffix)),
                |b| {
                    b.iter(|| {
                        let mut rng = ark_std::test_rng();
                        let (ck, _, _) =
                            keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);
                        let attributes: Vec<Fr> =
                            (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                        UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut rng)
                    })
                },
            );
        }

        group.finish();
    }

    // tIssue benchmarks
    {
        let mut group = c.benchmark_group("tIssue");
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(5));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            group.bench_function(
                BenchmarkId::from_parameter(format!("tIssue_{}", id_suffix)),
                |b| {
                    b.iter(|| {
                        let mut rng = ark_std::test_rng();

                        // Generate parameters
                        let (ck, _, ts_keys) =
                            keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);

                        // Create signers
                        let signers: Vec<_> = ts_keys
                            .sk_shares
                            .iter()
                            .zip(ts_keys.vk_shares.iter())
                            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                            .collect();

                        // Create credential
                        let attributes: Vec<Fr> =
                            (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                        let (mut credential, credential_request) =
                            UserProtocol::request_credential(
                                ck.clone(),
                                Some(&attributes),
                                &mut rng,
                            )
                            .expect("Failed to create credential request");

                        // Collect signature shares
                        let signature_shares = UserProtocol::collect_signature_shares(
                            &signers,
                            &credential_request,
                            threshold,
                        )
                        .expect("Failed to collect signature shares");

                        // Verify signature shares
                        let verified_shares = UserProtocol::verify_signature_shares(
                            &ck,
                            &ts_keys.vk_shares,
                            &credential_request,
                            &signature_shares,
                            threshold,
                        )
                        .expect("Failed to verify signature shares");

                        // Aggregate shares
                        let blindings = credential.get_blinding_factors();
                        UserProtocol::aggregate_shares(
                            &ck,
                            &verified_shares,
                            &blindings,
                            threshold,
                            &credential_request.h,
                        )
                    })
                },
            );
        }

        group.finish();
    }

    // Prove benchmarks
    {
        let mut group = c.benchmark_group("Prove");
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(5));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            group.bench_function(
                BenchmarkId::from_parameter(format!("Prove_{}", id_suffix)),
                |b| {
                    b.iter(|| {
                        let mut rng = ark_std::test_rng();

                        // Generate parameters
                        let (ck, _, ts_keys) =
                            keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);

                        // Create signers
                        let signers: Vec<_> = ts_keys
                            .sk_shares
                            .iter()
                            .zip(ts_keys.vk_shares.iter())
                            .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                            .collect();

                        // Create credential
                        let attributes: Vec<Fr> =
                            (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                        let (mut credential, credential_request) =
                            UserProtocol::request_credential(
                                ck.clone(),
                                Some(&attributes),
                                &mut rng,
                            )
                            .expect("Failed to create credential request");

                        // Collect signature shares
                        let signature_shares = UserProtocol::collect_signature_shares(
                            &signers,
                            &credential_request,
                            threshold,
                        )
                        .expect("Failed to collect signature shares");

                        // Verify signature shares
                        let verified_shares = UserProtocol::verify_signature_shares(
                            &ck,
                            &ts_keys.vk_shares,
                            &credential_request,
                            &signature_shares,
                            threshold,
                        )
                        .expect("Failed to verify signature shares");

                        // Aggregate shares
                        let blindings = credential.get_blinding_factors();
                        let threshold_signature = UserProtocol::aggregate_shares(
                            &ck,
                            &verified_shares,
                            &blindings,
                            threshold,
                            &credential_request.h,
                        )
                        .expect("Failed to aggregate signature shares");

                        // Attach signature
                        credential.attach_signature(threshold_signature);

                        // Show (generate presentation)
                        UserProtocol::show(&credential, &mut rng)
                    })
                },
            );
        }

        group.finish();
    }

    // Verify benchmarks
    {
        let mut group = c.benchmark_group("Verify");
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(5));

        for &(n_participants, threshold, l_attributes) in &configs {
            let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

            // Debug message to track progress
            println!("Setting up verification benchmark for: {}", id_suffix);

            // Set up the test environment first
            let mut setup_rng = ark_std::test_rng();
            let (ck, vk, ts_keys) =
                keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut setup_rng);

            // Create signers for all participants
            let signers: Vec<_> = ts_keys
                .sk_shares
                .iter()
                .zip(ts_keys.vk_shares.iter())
                .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                .collect();

            // Debug: Check how many signers we have
            println!("  - Number of signers: {}", signers.len());

            // Create credential with attributes
            let attributes: Vec<Fr> = (0..l_attributes)
                .map(|_| Fr::rand(&mut setup_rng))
                .collect();
            let (mut credential, credential_request) =
                UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut setup_rng)
                    .expect("Failed to create credential request");

            // Collect signature shares
            println!(
                "  - Collecting signature shares from {} signers with threshold {}",
                signers.len(),
                threshold
            );
            let signature_shares = match UserProtocol::collect_signature_shares(
                &signers,
                &credential_request,
                threshold,
            ) {
                Ok(shares) => {
                    println!(
                        "  - Successfully collected {} signature shares",
                        shares.len()
                    );
                    shares
                }
                Err(e) => {
                    println!("  - Failed to collect signature shares: {:?}", e);
                    panic!("Failed to collect signature shares: {:?}", e);
                }
            };

            // Verify signature shares
            println!("  - Verifying {} signature shares", signature_shares.len());
            let verified_shares = match UserProtocol::verify_signature_shares(
                &ck,
                &ts_keys.vk_shares,
                &credential_request,
                &signature_shares,
                threshold,
            ) {
                Ok(shares) => {
                    println!(
                        "  - Successfully verified {} signature shares",
                        shares.len()
                    );
                    shares
                }
                Err(e) => {
                    println!("  - Failed to verify signature shares: {:?}", e);
                    panic!("Failed to verify signature shares: {:?}", e);
                }
            };

            // Aggregate shares
            println!(
                "  - Aggregating {} verified shares (need {} valid shares)",
                verified_shares.len(),
                threshold
            );
            let threshold_signature = match UserProtocol::aggregate_shares(
                &ck,
                &verified_shares,
                &blindings,
                threshold,
                &credential_request.h,
            ) {
                Ok(sig) => {
                    println!("  - Successfully aggregated signature");
                    sig
                }
                Err(e) => {
                    println!("  - Failed to aggregate signature shares: {:?}", e);
                    panic!("Failed to aggregate signature shares: {:?}", e);
                }
            };

            // Attach signature to credential
            credential.attach_signature(threshold_signature);

            // Debug verification - try once before benchmarking
            let mut debug_rng = ark_std::test_rng();
            let (debug_sig, debug_cm, debug_cm_tilde, debug_proof) =
                UserProtocol::show(&credential, &mut debug_rng)
                    .expect("Failed to generate debug presentation");

            match VerifierProtocol::verify(
                &ck,
                &vk,
                &debug_cm,
                &debug_cm_tilde,
                &debug_sig,
                &debug_proof,
            ) {
                Ok(true) => println!("Debug verification for {} successful", id_suffix),
                Ok(false) => println!(
                    "Debug verification for {} failed (returned false)",
                    id_suffix
                ),
                Err(e) => println!("Debug verification for {} error: {:?}", id_suffix, e),
            }

            // Now benchmark only the verification with fresh presentations each time
            group.bench_function(
                BenchmarkId::from_parameter(format!("Verify_{}", id_suffix)),
                |b| {
                    b.iter_with_setup(
                        // Setup generates a fresh presentation each time
                        || {
                            let mut rng = ark_std::test_rng();
                            UserProtocol::show(&credential, &mut rng)
                                .expect("Failed to generate presentation")
                        },
                        // Use the fresh presentation for verification
                        |(randomized_sig, commitment, commitment_tilde, proof)| {
                            VerifierProtocol::verify(
                                &ck,
                                &vk,
                                &commitment,
                                &commitment_tilde,
                                &randomized_sig,
                                &proof,
                            )
                            .expect("Failed to verify credential")
                        },
                    )
                },
            );
        }

        group.finish();
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_threshold_ps
);
criterion_main!(benches);
