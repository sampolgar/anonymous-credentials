use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt::anon_cred_improved::{AnonCredProtocolImproved, ShowCredentialImproved, UserCred};
use ps_utt::signature::PSUTTSignatureImproved;
use std::time::Duration;

// Improved protocol test setup structure
struct ImprovedTestSetup<E: Pairing> {
    protocol: AnonCredProtocolImproved<E>,
    user_cred: UserCred<E>,
    proof: Vec<u8>,
    signature: PSUTTSignatureImproved<E>,
    presentation: ShowCredentialImproved<E>,
}

// Initialize an improved protocol test setup
fn setup_improved_protocol(msg_size: usize) -> ImprovedTestSetup<Bls12_381> {
    let mut rng = ark_std::test_rng();

    // Create protocol instance
    let protocol = AnonCredProtocolImproved::<Bls12_381>::new(msg_size, &mut rng);

    // Generate user credentials
    let user_cred = UserCred::<Bls12_381>::new_random_messages(&protocol.pp);

    // Generate proof
    let proof = protocol.obtain(&user_cred).expect("Failed to create proof");

    // Issue credential
    let signature = protocol
        .issue(&user_cred.commitment.cmg2, &proof)
        .expect("Failed to issue credential");

    // Create presentation
    let presentation = protocol
        .show(&user_cred.commitment, &signature, &mut rng)
        .expect("Failed to show credential");

    ImprovedTestSetup {
        protocol,
        user_cred,
        proof,
        signature,
        presentation,
    }
}

/// Benchmark function for improved PS-UTT protocol
fn benchmark_psutt_imp(c: &mut Criterion) {
    let mut group = c.benchmark_group("ps_utt_anoncreds_imp");
    println!("Starting PS-UTT Improved AnonCred protocol benchmarks");

    // Configure benchmark parameters
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(15));

    // Message sizes to benchmark
    static MESSAGE_SIZES: [usize; 8] = [2, 5, 10, 15, 20, 30, 40, 128];

    for &msg_size in &MESSAGE_SIZES {
        println!("Benchmarking with {} messages", msg_size);

        // Set up test environment for improved protocol
        let imp_setup = setup_improved_protocol(msg_size);

        // Benchmark Obtain
        let obtain_id = BenchmarkId::from_parameter(format!("obtain_messages_{}", msg_size));
        group.bench_function(obtain_id, |b| {
            b.iter(|| {
                imp_setup
                    .protocol
                    .obtain(&imp_setup.user_cred)
                    .expect("Failed to obtain credential")
            })
        });

        // Benchmark Issue
        let issue_id = BenchmarkId::from_parameter(format!("issue_messages_{}", msg_size));
        group.bench_function(issue_id, |b| {
            b.iter(|| {
                imp_setup
                    .protocol
                    .issue(&imp_setup.user_cred.commitment.cmg2, &imp_setup.proof)
                    .expect("Failed to issue credential")
            })
        });

        // Benchmark Show
        let show_id = BenchmarkId::from_parameter(format!("show_messages_{}", msg_size));
        group.bench_function(show_id, |b| {
            let mut rng = ark_std::test_rng();
            b.iter(|| {
                imp_setup
                    .protocol
                    .show(
                        &imp_setup.user_cred.commitment,
                        &imp_setup.signature,
                        &mut rng,
                    )
                    .expect("Failed to show credential")
            })
        });

        // Benchmark Verify
        let verify_id = BenchmarkId::from_parameter(format!("verify_messages_{}", msg_size));
        group.bench_function(verify_id, |b| {
            b.iter(|| {
                imp_setup
                    .protocol
                    .verify(&imp_setup.presentation)
                    .expect("Failed to verify credential")
            })
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_psutt_imp
);
criterion_main!(benches);
