use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps::anon_cred::{PSAnonCredProtocol, ShowCredential, UserCred};
use ps::signature::PSSignature;
use std::time::Duration;

// Test setup structure for PS AnonCred benchmarks
struct PSAnonCredTestSetup<E: Pairing> {
    protocol: PSAnonCredProtocol<E>,
    user_cred: UserCred<E>,
    proof: Vec<u8>,
    blind_signature: PSSignature<E>,
    signature: PSSignature<E>,
    presentation: ShowCredential,
}

// Initialize a protocol test setup
fn setup_ps_anoncred_protocol(msg_size: usize) -> PSAnonCredTestSetup<Bls12_381> {
    let mut rng = ark_std::test_rng();

    // Create protocol instance
    let protocol = PSAnonCredProtocol::<Bls12_381>::new(msg_size, &mut rng);

    // Generate user credentials
    let user_cred = UserCred::<Bls12_381>::new_random_messages(msg_size);

    // Generate proof
    let proof = protocol.obtain(&user_cred).expect("Failed to create proof");

    // Issue credential
    let blind_signature = protocol
        .issue(&proof, &mut rng)
        .expect("Failed to issue credential");

    // Unblind signature
    let signature = PSAnonCredProtocol::complete_signature(&blind_signature, &user_cred.t);

    // Create presentation
    let presentation = protocol
        .show(&signature, &user_cred, &mut rng)
        .expect("Failed to show credential");

    PSAnonCredTestSetup {
        protocol,
        user_cred,
        proof,
        blind_signature,
        signature,
        presentation,
    }
}

/// Benchmark function for PS AnonCred protocol
fn benchmark_ps_anoncred_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("ps_anoncreds");
    println!("Starting PS AnonCred protocol benchmarks");

    // Configure benchmark parameters
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(15));

    // Message sizes to benchmark
    static MESSAGE_SIZES: [usize; 8] = [2, 5, 10, 15, 20, 30, 40, 128];

    for &msg_size in &MESSAGE_SIZES {
        println!("Benchmarking with {} messages", msg_size);

        // Set up test environment
        let setup = setup_ps_anoncred_protocol(msg_size);

        // Benchmark Obtain
        let obtain_id = BenchmarkId::from_parameter(format!("ps_obtain_messages_{}", msg_size));
        group.bench_function(obtain_id, |b| {
            b.iter(|| {
                setup
                    .protocol
                    .obtain(&setup.user_cred)
                    .expect("Failed to obtain credential")
            })
        });

        // Benchmark Issue
        let issue_id = BenchmarkId::from_parameter(format!("ps_issue_messages_{}", msg_size));
        group.bench_function(issue_id, |b| {
            let mut rng = ark_std::test_rng();
            b.iter(|| {
                setup
                    .protocol
                    .issue(&setup.proof, &mut rng)
                    .expect("Failed to issue credential")
            })
        });

        // Benchmark Show
        let show_id = BenchmarkId::from_parameter(format!("ps_show_messages_{}", msg_size));
        group.bench_function(show_id, |b| {
            let mut rng = ark_std::test_rng();
            b.iter(|| {
                setup
                    .protocol
                    .show(&setup.signature, &setup.user_cred, &mut rng)
                    .expect("Failed to show credential")
            })
        });

        // Benchmark Verify
        let verify_id = BenchmarkId::from_parameter(format!("ps_verify_messages_{}", msg_size));
        group.bench_function(verify_id, |b| {
            b.iter(|| {
                setup
                    .protocol
                    .verify(&setup.presentation)
                    .expect("Failed to verify credential")
            })
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_ps_anoncred_protocol
);
criterion_main!(benches);
