use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

// Import your crate modules
use bbs_plus::anon_cred::AnonCredProtocol;
use bbs_plus::test_helpers::TestSetup;

/// Benchmark function for AnonCred protocol with different message sizes
fn benchmark_anoncred_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs_plus_anoncreds");
    println!("Starting BBSPlus AnonCred protocol benchmarks");

    // Configure benchmark parameters
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));

    // Message sizes to benchmark
    static MESSAGE_SIZES: [usize; 6] = [2, 5, 10, 15, 20, 30];

    for &msg_size in &MESSAGE_SIZES {
        println!("Benchmarking with {} messages", msg_size);

        // Setup phase using TestSetup
        let mut rng = ark_std::test_rng();
        let setup = TestSetup::<Bls12_381>::new(&mut rng, msg_size);

        // Pre-generate data for the benchmarks
        let (pre_commitment, s_prime) =
            AnonCredProtocol::obtain(&setup.pp, &setup.pk, &setup.messages, &mut rng)
                .expect("Failed to create commitment");

        let issuer_response =
            AnonCredProtocol::issue(&setup.pp, &setup.sk, &setup.pk, &pre_commitment, &mut rng)
                .expect("Failed to issue credential");

        let signature = AnonCredProtocol::complete_signature(&s_prime, &issuer_response);

        // Also use the existing signature from TestSetup for show/verify
        let (_, proof_from_setup) = AnonCredProtocol::show(
            &setup.pp,
            &setup.pk,
            &setup.signature,
            &setup.messages,
            &mut rng,
        )
        .expect("Failed to show credential");

        // Benchmark Obtain
        let obtain_id =
            BenchmarkId::from_parameter(format!("bbs_plus_obtain_messages_{}", msg_size));
        group.bench_function(obtain_id, |b| {
            b.iter(|| {
                AnonCredProtocol::obtain(&setup.pp, &setup.pk, &setup.messages, &mut rng)
                    .expect("Failed to obtain")
            })
        });

        // Benchmark Issue
        let issue_id = BenchmarkId::from_parameter(format!("bbs_plus_issue_messages_{}", msg_size));
        group.bench_function(issue_id, |b| {
            b.iter(|| {
                AnonCredProtocol::issue(&setup.pp, &setup.sk, &setup.pk, &pre_commitment, &mut rng)
                    .expect("Failed to issue")
            })
        });

        // Benchmark Show
        let show_id = BenchmarkId::from_parameter(format!("bbs_plus_show_messages_{}", msg_size));
        group.bench_function(show_id, |b| {
            b.iter(|| {
                AnonCredProtocol::show(
                    &setup.pp,
                    &setup.pk,
                    &setup.signature,
                    &setup.messages,
                    &mut rng,
                )
                .expect("Failed to show")
            })
        });

        // Benchmark Verify
        let verify_id =
            BenchmarkId::from_parameter(format!("bbs_plus_verify_messages_{}", msg_size));
        group.bench_function(verify_id, |b| {
            b.iter(|| {
                AnonCredProtocol::verify(&setup.pp, &setup.pk, &proof_from_setup)
                    .expect("Failed to verify")
            })
        });
    }

    group.finish();
}

// Define your criterion groups and main
criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_anoncred_protocol
);
criterion_main!(benches);
