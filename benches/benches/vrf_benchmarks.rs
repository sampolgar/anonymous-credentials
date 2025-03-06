use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use crypto_benchmarks::vrf_utt2::{
    non_pairing_vrf_evaluate, non_pairing_vrf_verify, pairing_vrf_evaluate, pairing_vrf_verify,
    NonPairingVRFProof, PairingVRFProof, PublicParams,
};

fn benchmark_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vrf_benchmarks");

    // Configure benchmark parameters
    group
        .sample_size(10) // Number of samples to collect
        .measurement_time(Duration::from_secs(10)); // Total time to spend measuring

    // --- Setup for Pairing VRF ---
    let mut rng = test_rng();
    // Public parameters
    let pp = PublicParams::<Bls12_381>::new(&mut rng);
    // Input field elements
    let s_sender = Fr::rand(&mut rng);
    let pid_sender = Fr::rand(&mut rng);
    let sn = Fr::rand(&mut rng);
    let r = Fr::rand(&mut rng);
    let a_prime = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    // Precompute a proof for verification
    let (proof_pairing, _y) =
        pairing_vrf_evaluate(&pp, s_sender, pid_sender, sn, r, a_prime, t, &mut rng);

    // Benchmark pairing_vrf_evaluate
    {
        let mut rng = test_rng(); // RNG for evaluate, reused across iterations
        group.bench_function("pairing_vrf_evaluate", |b| {
            b.iter(|| pairing_vrf_evaluate(&pp, s_sender, pid_sender, sn, r, a_prime, t, &mut rng))
        });
    }

    // Benchmark pairing_vrf_verify
    group.bench_function("pairing_vrf_verify", |b| {
        b.iter(|| pairing_vrf_verify(&pp, &proof_pairing))
    });

    // --- Setup for Non-Pairing VRF ---
    // Generators
    let g1 = G1Affine::rand(&mut rng);
    let g2 = G1Affine::rand(&mut rng);
    let g3 = G1Affine::rand(&mut rng);
    let g4 = G1Affine::rand(&mut rng);
    let g5 = G1Affine::rand(&mut rng);
    let g = G1Affine::rand(&mut rng);
    // Input field elements
    let pid_sender = Fr::rand(&mut rng);
    let s_sender = Fr::rand(&mut rng);
    let sn = Fr::rand(&mut rng);
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let r3 = Fr::rand(&mut rng);
    let r4 = Fr::rand(&mut rng);
    let r5 = Fr::rand(&mut rng);
    // Precompute a proof for verification
    let (proof_non_pairing, _output) = non_pairing_vrf_evaluate(
        g1, g2, g3, g4, g5, g, pid_sender, s_sender, sn, r1, r2, r3, r4, r5, &mut rng,
    );

    // Benchmark non_pairing_vrf_evaluate
    {
        let mut rng = test_rng(); // RNG for evaluate, reused across iterations
        group.bench_function("non_pairing_vrf_evaluate", |b| {
            b.iter(|| {
                non_pairing_vrf_evaluate(
                    g1, g2, g3, g4, g5, g, pid_sender, s_sender, sn, r1, r2, r3, r4, r5, &mut rng,
                )
            })
        });
    }

    // Benchmark non_pairing_vrf_verify
    group.bench_function("non_pairing_vrf_verify", |b| {
        b.iter(|| non_pairing_vrf_verify(g1, g2, g3, g4, g5, g, &proof_non_pairing))
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_vrf
);
criterion_main!(benches);
