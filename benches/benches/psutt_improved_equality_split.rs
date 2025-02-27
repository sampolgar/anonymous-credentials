use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ps_utt::benchmark_helpers::{BenchmarkSetup, BenchmarkSetupImproved};
use ps_utt::commitment::Commitment;
use ps_utt::proofsystem::CommitmentProofs;
use ps_utt::test_helpers::{PSUttImprovedTestSetup, PSUttTestSetup};
use std::time::Duration;

fn benchmark_psutt_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("psutt_improved_equality_split");
    println!("Starting PSUTT Improved split benchmarks");

    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));

    // static CREDENTIAL_COUNTS: [usize; 19] = [
    //     2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    // ];
    static CREDENTIAL_COUNTS: [usize; 5] = [2, 5, 10, 20, 30];
    static MSG_COUNT: usize = 10;

    for cred_count in CREDENTIAL_COUNTS {
        // Setup phase (done once per credential count)
        let setup = BenchmarkSetupImproved::<Bls12_381>::new(cred_count, MSG_COUNT);

        // Pre-generate random values to use in both proving and verification
        let mut rng = ark_std::test_rng();
        let r_deltas: Vec<Fr> = (0..cred_count).map(|_| Fr::rand(&mut rng)).collect();
        let u_deltas: Vec<Fr> = (0..cred_count).map(|_| Fr::rand(&mut rng)).collect();

        // Generate the proof data once outside the benchmark
        let (randomized_sigs, randomized_commitments, proof) = {
            let mut randomized_sigs = Vec::with_capacity(cred_count);
            let mut randomized_commitments = Vec::with_capacity(cred_count);

            for i in 0..cred_count {
                let psutt_setup = &setup.psutt_setups[i];
                let r_delta = r_deltas[i];
                let u_delta = u_deltas[i];

                let randomized_sig =
                    psutt_setup
                        .signature
                        .rerandomize(&psutt_setup.pp, &r_delta, &u_delta);
                let randomized_commitment = psutt_setup.commitment.create_randomized(&r_delta);

                randomized_sigs.push(randomized_sig);
                randomized_commitments.push(randomized_commitment);
            }

            let proof = CommitmentProofs::prove_equality(&randomized_commitments).unwrap();
            (
                randomized_sigs.clone(),
                randomized_commitments.clone(),
                proof.clone(),
            )
        };

        // Benchmark Proving
        let prove_id = BenchmarkId::from_parameter(format!("prove_credentials_{}", cred_count));
        group.bench_function(prove_id, |b| {
            b.iter_with_large_drop(|| {
                let mut randomized_sigs = Vec::with_capacity(cred_count);
                let mut randomized_commitments = Vec::with_capacity(cred_count);

                // Proving phase
                for i in 0..cred_count {
                    let psutt_setup = &setup.psutt_setups[i];
                    let r_delta = r_deltas[i];
                    let u_delta = u_deltas[i];

                    let randomized_sig =
                        psutt_setup
                            .signature
                            .rerandomize(&psutt_setup.pp, &r_delta, &u_delta);
                    let randomized_commitment = psutt_setup.commitment.create_randomized(&r_delta);

                    randomized_sigs.push(randomized_sig);
                    randomized_commitments.push(randomized_commitment);
                }

                // Generate equality proof
                CommitmentProofs::prove_equality(&randomized_commitments).unwrap()
            })
        });

        // Benchmark Verification using the pre-generated outputs
        let verify_id = BenchmarkId::from_parameter(format!("verify_credentials_{}", cred_count));
        group.bench_function(verify_id, |b| {
            b.iter(|| {
                // Verify equality proof
                assert!(CommitmentProofs::verify_equality::<Bls12_381>(&proof).unwrap());

                // Verify signatures
                for i in 0..cred_count {
                    let sig_valid = randomized_sigs[i].verify_with_pairing_checker_improved(
                        &setup.psutt_setups[i].pp,
                        &setup.psutt_setups[i].vk,
                        &randomized_commitments[i].cmg1,
                    );
                    assert!(sig_valid);
                }
            })
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = benchmark_psutt_split,
);
criterion_main!(benches);
