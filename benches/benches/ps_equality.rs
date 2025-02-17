use ark_bls12_381::Bls12_381;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps::psproofs::PSProofs;
use ps::test_helpers::BenchmarkSetup;
use std::time::Duration;

fn benchmark_equality_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("ps_equality_proof");
    println!("Starting ps equalityproof benchmark");
    group
        .sample_size(10) // Reduce from 100 to handle longer runs
        .measurement_time(Duration::from_secs(25)); // Increase measurement window
                                                    // Define parameters as static arrays
                                                    // static CREDENTIAL_COUNTS: [usize; 4] = [2, 5, 10, 20];
    static CREDENTIAL_COUNTS: [usize; 19] = [
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];
    static MESSAGE_COUNTS: [usize; 4] = [2, 5, 10, 20];

    // for cred_count in CREDENTIAL_COUNTS {
    //     for msg_count in MESSAGE_COUNTS {
    //         let id =
    //             BenchmarkId::from_parameter(format!("creds_{}_msgs_{}", cred_count, msg_count));

    //         group.bench_with_input(
    //             id,
    //             &(cred_count, msg_count),
    //             |b, &(cred_count, msg_count)| {
    //                 let setup = BenchmarkSetup::<Bls12_381>::new(cred_count, msg_count);

    //                 b.iter(|| {
    //                     // Generate proofs
    //                     let proofs: Vec<_> = setup
    //                         .setups
    //                         .iter()
    //                         .map(|s| {
    //                             PSProofs::prove_with_userid(
    //                                 s,
    //                                 &setup.user_id_blindness,
    //                                 &setup.challenge,
    //                             )
    //                             .expect("Proof generation failed")
    //                         })
    //                         .collect();

    //                     // Verify proofs
    //                     PSProofs::verify_batch_equality::<Bls12_381>(&setup.setups, &proofs)
    //                         .expect("Verification failed");
    //                 });
    //             },
    //         );
    //     }
    // }
    static MSG_COUNT: usize = 10;
    for cred_count in CREDENTIAL_COUNTS {
        let id = BenchmarkId::from_parameter(format!("credentials_{}", cred_count));

        group.bench_with_input(id, &(cred_count), |b, &(cred_count)| {
            let setup = BenchmarkSetup::<Bls12_381>::new(cred_count, MSG_COUNT);

            b.iter(|| {
                // Generate proofs
                let proofs: Vec<_> = setup
                    .setups
                    .iter()
                    .map(|s| {
                        PSProofs::prove_with_userid(s, &setup.user_id_blindness, &setup.challenge)
                            .expect("Proof generation failed")
                    })
                    .collect();

                // Verify proofs
                PSProofs::verify_batch_equality::<Bls12_381>(&setup.setups, &proofs)
                    .expect("Verification failed");
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_equality_proof,
);
criterion_main!(benches);
