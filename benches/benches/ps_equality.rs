// In benches/proof_benchmarks.rs
use ark_bls12_381::Bls12_381;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps::psproofs::PSProofs;
use ps::test_helpers::create_ps_with_userid;
use ps::test_helpers::BenchmarkSetup;

fn benchmark_equality_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("equality_proof");
    println!("Starting equalityproof benchmark");
    // Define parameters as static arrays
    static CREDENTIAL_COUNTS: [usize; 4] = [2, 5, 10, 20];
    static MESSAGE_COUNTS: [usize; 4] = [2, 5, 10, 20];

    for cred_count in CREDENTIAL_COUNTS {
        for msg_count in MESSAGE_COUNTS {
            let id = BenchmarkId::new(
                format!("creds_{}_msgs_{}", cred_count, msg_count),
                format!("{},{}", cred_count, msg_count),
            );

            group.bench_with_input(
                id,
                &(cred_count, msg_count),
                |b, &(cred_count, msg_count)| {
                    let setup = BenchmarkSetup::<Bls12_381>::new(cred_count, msg_count);

                    b.iter(|| {
                        // Generate proofs
                        let proofs: Vec<_> = setup
                            .setups
                            .iter()
                            .map(|s| {
                                PSProofs::prove_with_userid(
                                    s,
                                    &setup.user_id_blindness,
                                    &setup.challenge,
                                )
                                .expect("Proof generation failed")
                            })
                            .collect();

                        // Verify proofs
                        PSProofs::verify_batch_equality::<Bls12_381>(&setup.setups, &proofs)
                            .expect("Verification failed");
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_equality_proof,
);
criterion_main!(benches);
