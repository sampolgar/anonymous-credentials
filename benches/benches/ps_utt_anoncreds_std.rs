use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt::anon_cred::{AnonCredProtocol, ShowCredential, UserCred};
use ps_utt::signature::PSUTTSignature;
use std::time::Duration;

// Standard protocol test setup structure
struct StandardTestSetup<E: Pairing> {
    protocol: AnonCredProtocol<E>,
    user_cred: UserCred<E>,
    proof: Vec<u8>,
    signature: PSUTTSignature<E>,
    presentation: ShowCredential<E>,
}

// Initialize a standard protocol test setup
fn setup_standard_protocol(msg_size: usize) -> StandardTestSetup<Bls12_381> {
    let mut rng = ark_std::test_rng();

    // Create protocol instance
    let protocol = AnonCredProtocol::<Bls12_381>::new(msg_size, &mut rng);

    // Generate user credentials
    let user_cred = UserCred::<Bls12_381>::new_random_messages(&protocol.pp);

    // Generate proof
    let proof = protocol.obtain(&user_cred).expect("Failed to create proof");

    // Issue credential
    let signature = protocol.issue(&proof).expect("Failed to issue credential");

    // Create presentation
    let presentation = protocol
        .show(&user_cred.commitment, &signature, &mut rng)
        .expect("Failed to show credential");

    StandardTestSetup {
        protocol,
        user_cred,
        proof,
        signature,
        presentation,
    }
}

/// Benchmark function for standard PS-UTT protocol
fn benchmark_psutt_std(c: &mut Criterion) {
    let mut group = c.benchmark_group("ps_utt_anoncreds_std");
    println!("Starting PS-UTT Standard AnonCred protocol benchmarks");

    // Configure benchmark parameters
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(15));

    // Message sizes to benchmark
    static MESSAGE_SIZES: [usize; 8] = [2, 5, 10, 15, 20, 30, 40, 128];

    for &msg_size in &MESSAGE_SIZES {
        println!("Benchmarking with {} messages", msg_size);

        // Set up test environment for standard protocol
        let std_setup = setup_standard_protocol(msg_size);

        // Benchmark Obtain
        let obtain_id = BenchmarkId::from_parameter(format!("obtain_messages_{}", msg_size));
        group.bench_function(obtain_id, |b| {
            b.iter(|| {
                std_setup
                    .protocol
                    .obtain(&std_setup.user_cred)
                    .expect("Failed to obtain credential")
            })
        });

        // Benchmark Issue
        let issue_id = BenchmarkId::from_parameter(format!("issue_messages_{}", msg_size));
        group.bench_function(issue_id, |b| {
            b.iter(|| {
                std_setup
                    .protocol
                    .issue(&std_setup.proof)
                    .expect("Failed to issue credential")
            })
        });

        // Benchmark Show
        let show_id = BenchmarkId::from_parameter(format!("show_messages_{}", msg_size));
        group.bench_function(show_id, |b| {
            let mut rng = ark_std::test_rng();
            b.iter(|| {
                std_setup
                    .protocol
                    .show(
                        &std_setup.user_cred.commitment,
                        &std_setup.signature,
                        &mut rng,
                    )
                    .expect("Failed to show credential")
            })
        });

        // Benchmark Verify
        let verify_id = BenchmarkId::from_parameter(format!("verify_messages_{}", msg_size));
        group.bench_function(verify_id, |b| {
            b.iter(|| {
                std_setup
                    .protocol
                    .verify(&std_setup.presentation)
                    .expect("Failed to verify credential")
            })
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_psutt_std
);
criterion_main!(benches);
