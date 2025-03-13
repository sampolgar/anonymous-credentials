// use ark_bls12_381::Bls12_381;
// use ark_ec::pairing::Pairing;
// use ark_ff::UniformRand;
// use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
// use ps_utt_ts::credential::{Credential, CredentialCommitments};
// use ps_utt_ts::keygen::{ThresholdKeys, VerificationKey, VerificationKeyShare};
// use ps_utt_ts::protocol::{IssuerProtocol, UserProtocol, VerifierProtocol};
// use ps_utt_ts::signature::{PartialSignature, ThresholdSignature};
// use ps_utt_ts::signer::Signer;
// use ps_utt_ts::symmetric_commitment::SymmetricCommitmentKey;
// use std::time::Duration;

// // Threshold PS test setup structure - not using lifetimes to avoid complexity
// struct ThresholdTestSetup<E: Pairing> {
//     // Common parameters
//     ck: SymmetricCommitmentKey<E>,
//     vk: VerificationKey<E>,
//     ts_keys: ThresholdKeys<E>,

//     // We'll store the full signer state but create them on demand for benchmarks

//     // Credential
//     credential: Credential<E>,
//     credential_request: CredentialCommitments<E>,

//     // Signature data
//     signature_shares: Vec<(usize, PartialSignature<E>)>,
//     threshold_signature: Option<ThresholdSignature<E>>,

//     // Presentation data
//     randomized_sig: Option<ThresholdSignature<E>>,
//     commitment: Option<E::G1Affine>,
//     commitment_tilde: Option<E::G2Affine>,
//     proof: Option<Vec<u8>>,
// }

// // Initialize a threshold protocol test setup
// fn setup_threshold_protocol(
//     num_issuers: usize,
//     threshold: usize,
//     num_attributes: usize,
// ) -> ThresholdTestSetup<Bls12_381> {
//     let mut rng = ark_std::test_rng();

//     // Generate system parameters and keys
//     let (ck, vk, ts_keys) =
//         IssuerProtocol::setup::<Bls12_381>(threshold, num_issuers, num_attributes, &mut rng);

//     // Generate random attributes
//     let attributes = (0..num_attributes)
//         .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
//         .collect::<Vec<_>>();

//     // Create a credential request (initial setup only)
//     let (credential, credential_request) =
//         UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut rng)
//             .expect("Failed to create credential request");

//     ThresholdTestSetup {
//         ck,
//         vk,
//         ts_keys,
//         credential,
//         credential_request,
//         signature_shares: Vec::new(),
//         threshold_signature: None,
//         randomized_sig: None,
//         commitment: None,
//         commitment_tilde: None,
//         proof: None,
//     }
// }

// /// Benchmark function for threshold PS protocol
// fn benchmark_threshold_ps(c: &mut Criterion) {
//     // Test configurations to match tACT paper's parameters
//     let configs = [
//         // N=4, t=N/2+1=3, with n=30, 40, 128 attributes
//         (4, 3, 10),
//         (4, 3, 30),
//         // (4, 3, 40),
//         // (4, 3, 128),
//         // N=64, t=N/2+1=33, with n=30, 40, 128 attributes
//         (64, 33, 10),
//         (64, 33, 30),
//         // (64, 33, 40),
//         // (64, 33, 128),
//     ];

//     // Run TokenRequest benchmarks
//     {
//         let mut group = c.benchmark_group("TokenRequest");
//         group
//             .sample_size(10)
//             .measurement_time(Duration::from_secs(5));

//         for &(num_issuers, threshold, num_attributes) in &configs {
//             let id_suffix = format!("N{}_t{}_n{}", num_issuers, threshold, num_attributes);
//             let mut setup = setup_threshold_protocol(num_issuers, threshold, num_attributes);

//             // Benchmark TokenRequest
//             let id = BenchmarkId::from_parameter(format!("TokenRequest_{}", id_suffix));
//             group.bench_function(id, |b| {
//                 b.iter(|| {
//                     // TokenRequest benchmark code...
//                     let mut rng = ark_std::test_rng();
//                     let attributes = (0..num_attributes)
//                         .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
//                         .collect::<Vec<_>>();

//                     UserProtocol::request_credential(setup.ck.clone(), Some(&attributes), &mut rng)
//                         .expect("Failed to create credential request")
//                 });
//             });
//         }

//         group.finish(); // Release the mutable borrow before creating next group
//     }

//     // Run tIssue benchmarks
//     {
//         let mut group = c.benchmark_group("tIssue");
//         group
//             .sample_size(10)
//             .measurement_time(Duration::from_secs(5));

//         for &(num_issuers, threshold, num_attributes) in &configs {
//             let id_suffix = format!("N{}_t{}_n{}", num_issuers, threshold, num_attributes);
//             let mut setup = setup_threshold_protocol(num_issuers, threshold, num_attributes);

//             // tIssue benchmark setup and execution...
//             let tissue_id = BenchmarkId::from_parameter(format!("tIssue_{}", id_suffix));
//             group.bench_function(tissue_id, |b| {
//                 // Changed from tissue_group to group
//                 b.iter(|| {
//                     // Create fresh signers for the benchmark
//                     let signers: Vec<_> = (0..threshold + 1)
//                         .map(|i| {
//                             Signer::new(
//                                 &setup.ck,
//                                 &setup.ts_keys.sk_shares[i],
//                                 &setup.ts_keys.vk_shares[i],
//                             )
//                         })
//                         .collect();

//                     let signature_shares = UserProtocol::collect_signature_shares(
//                         &signers,
//                         &setup.credential_request,
//                         threshold,
//                     )
//                     .expect("Failed to collect signature shares");

//                     // Verify signature shares
//                     let verified_shares = UserProtocol::verify_signature_shares(
//                         &setup.ck,
//                         &setup.ts_keys.vk_shares,
//                         &setup.credential_request,
//                         &signature_shares,
//                         threshold,
//                     )
//                     .expect("Failed to verify signature shares");

//                     // Aggregate signature shares
//                     let blindings = setup.credential.get_blinding_factors();
//                     UserProtocol::aggregate_shares(
//                         &setup.ck,
//                         &verified_shares,
//                         &blindings,
//                         threshold,
//                         &setup.credential_request.h,
//                     )
//                     .expect("Failed to aggregate signature shares")
//                 })
//             });
//         }

//         group.finish();
//     }

//     // Run Prove benchmarks
//     {
//         let mut group = c.benchmark_group("Prove");
//         group
//             .sample_size(10)
//             .measurement_time(Duration::from_secs(5));

//         for &(num_issuers, threshold, num_attributes) in &configs {
//             let id_suffix = format!("N{}_t{}_n{}", num_issuers, threshold, num_attributes);
//             let mut setup = setup_threshold_protocol(num_issuers, threshold, num_attributes);

//             // Prepare the credential with signature for the show operation
//             // Create signers for the threshold signature
//             let signers: Vec<_> = (0..threshold + 1)
//                 .map(|i| {
//                     Signer::new(
//                         &setup.ck,
//                         &setup.ts_keys.sk_shares[i],
//                         &setup.ts_keys.vk_shares[i],
//                     )
//                 })
//                 .collect();

//             // Collect signature shares
//             let signature_shares = UserProtocol::collect_signature_shares(
//                 &signers,
//                 &setup.credential_request,
//                 threshold,
//             )
//             .expect("Failed to collect signature shares");

//             // Verify signature shares
//             let verified_shares = UserProtocol::verify_signature_shares(
//                 &setup.ck,
//                 &setup.ts_keys.vk_shares,
//                 &setup.credential_request,
//                 &signature_shares,
//                 threshold,
//             )
//             .expect("Failed to verify signature shares");

//             // Aggregate signature shares to get a valid threshold signature
//             let blindings = setup.credential.get_blinding_factors();
//             let threshold_signature = UserProtocol::aggregate_shares(
//                 &setup.ck,
//                 &verified_shares,
//                 &blindings,
//                 threshold,
//                 &setup.credential_request.h,
//             )
//             .expect("Failed to aggregate signature shares");

//             // Apply the signature to the credential
//             setup.credential.attach_signature(threshold_signature);

//             // Benchmark the show operation
//             let id = BenchmarkId::from_parameter(format!("Prove_{}", id_suffix));
//             group.bench_function(id, |b| {
//                 b.iter(|| {
//                     let mut rng = ark_std::test_rng();
//                     UserProtocol::show(&setup.credential, &mut rng)
//                         .expect("Failed to generate credential presentation")
//                 })
//             });
//         }

//         group.finish();
//     }

//     // Run Verify benchmarks
//     {
//         let mut group = c.benchmark_group("Verify");
//         group
//             .sample_size(10)
//             .measurement_time(Duration::from_secs(5));

//         for &(num_issuers, threshold, num_attributes) in &configs {
//             let id_suffix = format!("N{}_t{}_n{}", num_issuers, threshold, num_attributes);
//             let mut setup = setup_threshold_protocol(num_issuers, threshold, num_attributes);

//             // Prepare the credential with signature for verification
//             let signers: Vec<_> = (0..threshold + 1)
//                 .map(|i| {
//                     Signer::new(
//                         &setup.ck,
//                         &setup.ts_keys.sk_shares[i],
//                         &setup.ts_keys.vk_shares[i],
//                     )
//                 })
//                 .collect();

//             // Collect signature shares
//             let signature_shares = UserProtocol::collect_signature_shares(
//                 &signers,
//                 &setup.credential_request,
//                 threshold,
//             )
//             .expect("Failed to collect signature shares");

//             // Verify signature shares
//             let verified_shares = UserProtocol::verify_signature_shares(
//                 &setup.ck,
//                 &setup.ts_keys.vk_shares,
//                 &setup.credential_request,
//                 &signature_shares,
//                 threshold,
//             )
//             .expect("Failed to verify signature shares");

//             // Aggregate signature shares
//             let blindings = setup.credential.get_blinding_factors();
//             let threshold_signature = UserProtocol::aggregate_shares(
//                 &setup.ck,
//                 &verified_shares,
//                 &blindings,
//                 threshold,
//                 &setup.credential_request.h,
//             )
//             .expect("Failed to aggregate signature shares");

//             // Apply the signature to the credential
//             setup.credential.attach_signature(threshold_signature);

//             // Benchmark verification with fresh presentations each time
//             let verify_id = BenchmarkId::from_parameter(format!("Verify_{}", id_suffix));

//             // Debug - try a single verification before benchmarking
//             let mut debug_rng = ark_std::test_rng();
//             let (debug_sig, debug_cm, debug_cm_tilde, debug_proof) =
//                 UserProtocol::show(&setup.credential, &mut debug_rng)
//                     .expect("Failed to generate debug presentation");

//             match VerifierProtocol::verify(
//                 &setup.ck,
//                 &setup.vk,
//                 &debug_cm,
//                 &debug_cm_tilde,
//                 &debug_sig,
//                 &debug_proof,
//             ) {
//                 Ok(true) => println!("Debug verification for {} successful", id_suffix),
//                 Ok(false) => println!(
//                     "Debug verification for {} failed (returned false)",
//                     id_suffix
//                 ),
//                 Err(e) => println!("Debug verification for {} error: {:?}", id_suffix, e),
//             }

//             // Use iter_with_setup to generate a fresh presentation for each verification
//             group.bench_function(verify_id, |b| {
//                 b.iter_with_setup(
//                     // Setup generates a fresh presentation each time
//                     || {
//                         let mut rng = ark_std::test_rng();
//                         UserProtocol::show(&setup.credential, &mut rng)
//                             .expect("Failed to generate presentation")
//                     },
//                     // Use the fresh presentation for verification
//                     |(randomized_sig, commitment, commitment_tilde, proof)| {
//                         VerifierProtocol::verify(
//                             &setup.ck,
//                             &setup.vk,
//                             &commitment,
//                             &commitment_tilde,
//                             &randomized_sig,
//                             &proof,
//                         )
//                         .expect("Failed to verify credential")
//                     },
//                 )
//             });
//         }

//         group.finish();
//     }
// }

// criterion_group!(
//     name = benches;
//     config = Criterion::default();
//     targets = benchmark_threshold_ps
// );
// criterion_main!(benches);
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt_ts::credential::Credential;
use ps_utt_ts::keygen::keygen;
use ps_utt_ts::protocol::{IssuerProtocol, UserProtocol, VerifierProtocol};
use ps_utt_ts::signer::Signer;
use std::time::Duration;

// Constants mirroring the test case
const THRESHOLD: usize = 2;
const N_PARTICIPANTS: usize = 5;
const L_ATTRIBUTES: usize = 3;

/// Benchmark function that directly uses the test case structure
fn benchmark_threshold_ps(c: &mut Criterion) {
    // Define benchmark groups
    let mut token_request_group = c.benchmark_group("TokenRequest");
    let mut tissue_group = c.benchmark_group("tIssue");
    let mut prove_group = c.benchmark_group("Prove");
    let mut verify_group = c.benchmark_group("Verify");

    // Configure benchmark parameters
    for group in [
        &mut token_request_group,
        &mut tissue_group,
        &mut prove_group,
        &mut verify_group,
    ] {
        group
            .sample_size(10)
            .measurement_time(Duration::from_secs(5));
    }

    // Test configurations - just use the test case for now
    let configs = [
        (N_PARTICIPANTS, THRESHOLD, L_ATTRIBUTES),
        // Once working, add more configurations
    ];

    for &(n_participants, threshold, l_attributes) in &configs {
        let id_suffix = format!("N{}_t{}_n{}", n_participants, threshold, l_attributes);

        // TokenRequest benchmark
        token_request_group.bench_function(
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

        // tIssue benchmark
        tissue_group.bench_function(
            BenchmarkId::from_parameter(format!("tIssue_{}", id_suffix)),
            |b| {
                b.iter(|| {
                    let mut rng = ark_std::test_rng();

                    // 1. Generate parameters
                    let (ck, _, ts_keys) =
                        keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);

                    // Create signers
                    let signers: Vec<_> = ts_keys
                        .sk_shares
                        .iter()
                        .zip(ts_keys.vk_shares.iter())
                        .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                        .collect();

                    // 2. Create credential
                    let attributes: Vec<Fr> =
                        (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                    let (mut credential, credential_request) =
                        UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut rng)
                            .expect("Failed to create credential request");

                    // 3. Collect signature shares
                    let signature_shares = UserProtocol::collect_signature_shares(
                        &signers,
                        &credential_request,
                        threshold,
                    )
                    .expect("Failed to collect signature shares");

                    // 4. Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &credential_request,
                        &signature_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // 5. Aggregate shares
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

        // Prove benchmark
        prove_group.bench_function(
            BenchmarkId::from_parameter(format!("Prove_{}", id_suffix)),
            |b| {
                b.iter(|| {
                    let mut rng = ark_std::test_rng();

                    // 1. Generate parameters
                    let (ck, _, ts_keys) =
                        keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);

                    // Create signers
                    let signers: Vec<_> = ts_keys
                        .sk_shares
                        .iter()
                        .zip(ts_keys.vk_shares.iter())
                        .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                        .collect();

                    // 2. Create credential
                    let attributes: Vec<Fr> =
                        (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                    let (mut credential, credential_request) =
                        UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut rng)
                            .expect("Failed to create credential request");

                    // 3. Collect signature shares
                    let signature_shares = UserProtocol::collect_signature_shares(
                        &signers,
                        &credential_request,
                        threshold,
                    )
                    .expect("Failed to collect signature shares");

                    // 4. Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &credential_request,
                        &signature_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // 5. Aggregate shares
                    let blindings = credential.get_blinding_factors();
                    let threshold_signature = UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &credential_request.h,
                    )
                    .expect("Failed to aggregate signature shares");

                    // 6. Attach signature
                    credential.attach_signature(threshold_signature);

                    // 7. Show (generate presentation)
                    UserProtocol::show(&credential, &mut rng)
                })
            },
        );

        // Verify benchmark
        verify_group.bench_function(
            BenchmarkId::from_parameter(format!("Verify_{}", id_suffix)),
            |b| {
                b.iter(|| {
                    let mut rng = ark_std::test_rng();

                    // 1. Generate parameters
                    let (ck, vk, ts_keys) =
                        keygen::<Bls12_381>(threshold, n_participants, l_attributes, &mut rng);

                    // Create signers
                    let signers: Vec<_> = ts_keys
                        .sk_shares
                        .iter()
                        .zip(ts_keys.vk_shares.iter())
                        .map(|(sk_share, vk_share)| Signer::new(&ck, sk_share, vk_share))
                        .collect();

                    // 2. Create credential
                    let attributes: Vec<Fr> =
                        (0..l_attributes).map(|_| Fr::rand(&mut rng)).collect();
                    let (mut credential, credential_request) =
                        UserProtocol::request_credential(ck.clone(), Some(&attributes), &mut rng)
                            .expect("Failed to create credential request");

                    // 3. Collect signature shares
                    let signature_shares = UserProtocol::collect_signature_shares(
                        &signers,
                        &credential_request,
                        threshold,
                    )
                    .expect("Failed to collect signature shares");

                    // 4. Verify signature shares
                    let verified_shares = UserProtocol::verify_signature_shares(
                        &ck,
                        &ts_keys.vk_shares,
                        &credential_request,
                        &signature_shares,
                        threshold,
                    )
                    .expect("Failed to verify signature shares");

                    // 5. Aggregate shares
                    let blindings = credential.get_blinding_factors();
                    let threshold_signature = UserProtocol::aggregate_shares(
                        &ck,
                        &verified_shares,
                        &blindings,
                        threshold,
                        &credential_request.h,
                    )
                    .expect("Failed to aggregate signature shares");

                    // 6. Attach signature
                    credential.attach_signature(threshold_signature);

                    // 7. Show (generate presentation)
                    let (randomized_sig, commitment, commitment_tilde, proof) =
                        UserProtocol::show(&credential, &mut rng)
                            .expect("Failed to generate credential presentation");

                    // 8. Verify
                    // Just to be safe, explicitly handle the result
                    let result = VerifierProtocol::verify(
                        &ck,
                        &vk,
                        &commitment,
                        &commitment_tilde,
                        &randomized_sig,
                        &proof,
                    );

                    match &result {
                        Ok(valid) => {
                            if !valid {
                                println!("❌ Verification returned false");
                                panic!("Verification returned false");
                            }
                        }
                        Err(e) => {
                            println!("❌ Verification error: {:?}", e);
                            panic!("Verification error: {:?}", e);
                        }
                    }

                    result
                })
            },
        );
    }

    token_request_group.finish();
    tissue_group.finish();
    prove_group.finish();
    verify_group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_threshold_ps
);
criterion_main!(benches);
