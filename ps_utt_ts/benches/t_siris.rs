use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt_ts::credential::Credential;
use ps_utt_ts::credential::CredentialState;
use ps_utt_ts::keygen::keygen;
use ps_utt_ts::protocol::{IssuerProtocol, UserProtocol, VerifierProtocol};
use ps_utt_ts::signature::{PartialSignature, ThresholdSignature};
use ps_utt_ts::signer::Signer;
use std::time::Duration;

/// Benchmark function for threshold PS protocol
fn benchmark_t_siris(c: &mut Criterion) {
    // Test configurations to match tACT paper's parameters
    let configs = [
        // N=4, t=N/2+1=3, with varying attribute sizes
        (4, 3, 4),
        // (4, 3, 8),
        // (4, 3, 16),
        // (4, 3, 32),
        // (4, 3, 64),
        // (4, 3, 128),

        // N=16, t=N/2+1=9, with varying attribute sizes
        // (16, 9, 4),
        // (16, 9, 8),
        // (16, 9, 16),
        // (16, 9, 32),
        // (16, 9, 64),
        // (16, 9, 128),

        // N=64, t=N/2+1=33, with varying attribute sizes
        // (64, 33, 4),
        // (64, 33, 8),
        // (64, 33, 16),
        // (64, 33, 32),
        // (64, 33, 64),
        // (64, 33, 128),
    ];

    // TokenRequest benchmarks

    // tIssue benchmarks

    // aggregate_verify benchmarks

    // aggregate_no_verify benchmarks
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_t_siris
);
criterion_main!(benches);
