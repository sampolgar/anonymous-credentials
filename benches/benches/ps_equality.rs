// // use ark_bls12_381::Bls12_381;
// // use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
// // use ps::psproofs::PSProofs;
// // use ps::test_helpers::BenchmarkSetup;
// // use std::time::Duration;

// // fn benchmark_equality_proof(c: &mut Criterion) {
// //     let mut group = c.benchmark_group("ps_equality_proof");
// //     println!("Starting ps equalityproof benchmark");
// //     group
// //         .sample_size(3)
// //         .measurement_time(Duration::from_secs(5));

// //     static CREDENTIAL_COUNTS: [usize; 5] = [2, 5, 10, 20, 30];
// //     static MSG_COUNT: usize = 10;

// //     for cred_count in CREDENTIAL_COUNTS {
// //         let id = BenchmarkId::from_parameter(format!("credentials_{}", cred_count));

// //         group.bench_with_input(id, &(cred_count), |b, &cred_count| {
// //             let setup = BenchmarkSetup::<Bls12_381>::new(cred_count, MSG_COUNT);

// //             b.iter(|| {
// //                 // Generate proofs
// //                 let proofs: Vec<_> = setup
// //                     .setups
// //                     .iter()
// //                     .map(|s| {
// //                         PSProofs::prove_with_userid(s, &setup.user_id_blindness, &setup.challenge)
// //                             .expect("Proof generation failed")
// //                     })
// //                     .collect();

// //                 // Verify proofs
// //                 PSProofs::verify_batch_equality::<Bls12_381>(&setup.setups, &proofs)
// //                     .expect("Verification failed");
// //             });
// //         });
// //     }

// //     group.finish();
// // }

// // criterion_group!(
// //     name = benches;
// //     config = Criterion::default();
// //     targets = benchmark_equality_proof,
// // );
// // criterion_main!(benches);
// use ark_bls12_381::{Bls12_381, Fr};
// use ark_std::UniformRand;
// use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
// use ps::test_helpers::{BenchmarkSetup, PSTestSetup};
// use std::time::Duration;

// fn benchmark_ps_split(c: &mut Criterion) {
//     let mut group = c.benchmark_group("ps_equality_split");
//     println!("Starting PS equality proof split benchmark");

//     group
//         .sample_size(10)
//         .measurement_time(Duration::from_secs(10));

//     static CREDENTIAL_COUNTS: [usize; 5] = [2, 5, 10, 20, 30];
//     static MSG_COUNT: usize = 10;

//     // Pre-generate all setups for all credential counts before benchmarking
//     println!("Generating all credential setups before benchmarking...");
//     let all_setups: Vec<BenchmarkSetup<Bls12_381>> = CREDENTIAL_COUNTS
//         .iter()
//         .map(|&cred_count| {
//             println!("Generating setup for {} credentials", cred_count);
//             BenchmarkSetup::<Bls12_381>::new(cred_count, MSG_COUNT)
//         })
//         .collect();

//     for (setup_idx, cred_count) in CREDENTIAL_COUNTS.iter().enumerate() {
//         let setup = &all_setups[setup_idx];

//         // Benchmark Proving (including randomization)
//         let prove_id = BenchmarkId::from_parameter(format!("prove_credentials_{}", cred_count));
//         group.bench_function(prove_id, |b| {
//             b.iter_with_large_drop(|| {
//                 let mut rng = ark_std::test_rng();

//                 // First randomize all signatures by creating new PSTestSetups
//                 let randomized_setups: Vec<PSTestSetup<Bls12_381>> = setup
//                     .setups
//                     .iter()
//                     .map(|s| {
//                         let r_delta = Fr::rand(&mut rng);
//                         PSTestSetup {
//                             pk: s.pk.clone(),
//                             sk: s.sk.clone(),
//                             messages: s.messages.clone(),
//                             signature: s.signature.rerandomize(&r_delta),
//                         }
//                     })
//                     .collect();

//                 // Then generate proofs with randomized signatures
//                 randomized_setups
//                     .iter()
//                     .map(|s| {
//                         PSProofs::prove_with_userid(s, &setup.user_id_blindness, &setup.challenge)
//                             .expect("Proof generation failed")
//                     })
//                     .collect::<Vec<_>>()
//             })
//         });

//         // Benchmark Verification
//         let verify_id = BenchmarkId::from_parameter(format!("verify_credentials_{}", cred_count));
//         group.bench_function(verify_id, |b| {
//             // Pre-generate randomized credentials and proofs for verification benchmark
//             let mut rng = ark_std::test_rng();

//             // Randomize signatures by creating new PSTestSetups
//             let randomized_setups: Vec<PSTestSetup<Bls12_381>> = setup
//                 .setups
//                 .iter()
//                 .map(|s| {
//                     let r_delta = Fr::rand(&mut rng);
//                     PSTestSetup {
//                         pk: s.pk.clone(),
//                         sk: s.sk.clone(),
//                         messages: s.messages.clone(),
//                         signature: s.signature.rerandomize(&r_delta),
//                     }
//                 })
//                 .collect();

//             // Generate proofs using randomized signatures
//             let proofs: Vec<_> = randomized_setups
//                 .iter()
//                 .map(|s| {
//                     PSProofs::prove_with_userid(s, &setup.user_id_blindness, &setup.challenge)
//                         .expect("Proof generation failed")
//                 })
//                 .collect();

//             // Benchmark just the verification
//             b.iter(|| {
//                 PSProofs::verify_batch_equality::<Bls12_381>(&randomized_setups, &proofs)
//                     .expect("Verification failed")
//             });
//         });
//     }

//     group.finish();
// }

// criterion_group!(
//     name = benches;
//     config = Criterion::default();
//     targets = benchmark_ps_split,
// );
// criterion_main!(benches);
