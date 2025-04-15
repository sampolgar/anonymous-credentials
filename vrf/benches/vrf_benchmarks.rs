use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::{rand::Rng, test_rng};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use vrf::{
    dy::{DYPublicKey, DYSecretKey, DYVRFInput, DYVRF},
    p_dy::{PDYPublicKey, PDYSecretKey, PDYVRFInput, PDYVRF},
    p_dy_priv::{
        PDYPrivPublicKey, PDYPrivSecretKey, PDYPrivVRF, PDYPrivVRFInput, PDYPrivVRFWitness,
    },
    p_dy_priv_extra::{PDYPrivExtraVRF, PDYPrivExtraWitness},
};

// Number of runs for each benchmark - change to 10 for quicker testing
const NUM_RUNS: usize = 100;

fn bench_dy_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("dy");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = DYVRF::<Bls12_381>::new(&mut rng);

    // Generate keys
    let (sk, pk) = vrf.generate_keys(&mut rng);

    // Benchmark Eval + Prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            for _ in 0..NUM_RUNS {
                // Create new random input for each run
                let input = DYVRFInput {
                    x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
                };

                // Evaluate and generate proof
                let _output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");
            }
        })
    });

    // Pre-compute some outputs for verification benchmarks
    let inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| DYVRFInput {
            x: <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        })
        .collect();

    let outputs: Vec<_> = inputs
        .iter()
        .map(|input| vrf.evaluate(input, &sk).expect("Failed to evaluate VRF"))
        .collect();

    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                let is_valid = vrf.verify_direct(&inputs[i], &pk, &outputs[i]);
                assert!(is_valid, "DY-VRF verification failed");
            }
        })
    });

    // Benchmark verify (Optimized)
    group.bench_function("verify_optimized", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                let is_valid = vrf.verify_optimized(&inputs[i], &pk, &outputs[i]);
                assert!(is_valid, "DY-VRF optimized verification failed");
            }
        })
    });

    group.finish();
}

fn bench_p_dy_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("p_dy");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = PDYVRF::<G1Affine>::new(&mut rng);

    // Generate keys
    let (sk, pk) = vrf.generate_keys(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                // Create new random input
                let input = PDYVRFInput {
                    x: Fr::rand(&mut rng),
                };

                // Evaluate
                let output = vrf.evaluate(&input, &sk).expect("Failed to evaluate VRF");

                // Generate proof
                let _proof = vrf
                    .prove(&input, &sk, &output, &challenges[i], &mut rng)
                    .expect("Failed to generate proof");
            }
        })
    });

    // Pre-compute inputs, outputs, and proofs for verification benchmarks
    let inputs: Vec<_> = (0..NUM_RUNS)
        .map(|_| PDYVRFInput {
            x: Fr::rand(&mut rng),
        })
        .collect();

    let outputs: Vec<_> = inputs
        .iter()
        .map(|input| vrf.evaluate(input, &sk).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| {
            vrf.prove(&inputs[i], &sk, &outputs[i], &challenges[i], &mut rng)
                .expect("Failed to generate proof")
        })
        .collect();

    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                let is_valid = vrf.verify(&inputs[i], &pk, &outputs[i], &proofs[i], &challenges[i]);
                assert!(is_valid, "P-DY-VRF verification failed");
            }
        })
    });

    group.finish();
}

fn bench_p_dy_priv_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("p_dy_priv");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = PDYPrivVRF::<G1Affine>::new(&mut rng);

    // Generate keys
    let (sk, mut pk) = vrf.generate_keys(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                // Create input and commitment
                let x = Fr::rand(&mut rng);
                let (input, cm_x) = vrf.commit_to_input(&x, &mut rng);
                let mut pk_clone = PDYPrivPublicKey {
                    cm_sk: pk.cm_sk.clone(),
                    cm_x,
                };

                // Create witness
                let witness = PDYPrivVRFWitness {
                    sk: sk.sk,
                    r_sk: sk.r_sk,
                    x: input.x,
                    r_x: input.r_x,
                };

                // Evaluate
                let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");

                // Generate proof
                let _proof = vrf.prove_with_challenge(&witness, &output, &challenges[i], &mut rng);
            }
        })
    });

    // Create a tuple of (witness, commitment) to ensure they match
    let witnesses_and_commitments: Vec<(PDYPrivVRFWitness<Fr>, G1Affine)> = (0..NUM_RUNS)
        .map(|_| {
            // Generate random input
            let x = Fr::rand(&mut rng);
            // Generate commitment and randomness together
            let (input, cm_x) = vrf.commit_to_input(&x, &mut rng);

            // Create the witness with the SAME randomness used for commitment
            let witness = PDYPrivVRFWitness {
                sk: sk.sk,
                r_sk: sk.r_sk,
                x: input.x,
                r_x: input.r_x, // This is the important part - using same r_x
            };

            (witness, cm_x)
        })
        .collect();

    // Extract witnesses and create matching public keys
    let witnesses: Vec<_> = witnesses_and_commitments
        .iter()
        .map(|(w, _)| w.clone())
        .collect();
    let pks: Vec<PDYPrivPublicKey<G1Affine>> = witnesses_and_commitments
        .iter()
        .map(|(_, cm_x)| {
            PDYPrivPublicKey {
                cm_sk: pk.cm_sk.clone(),
                cm_x: *cm_x, // Using the commitment that matches the witness
            }
        })
        .collect();

    // Generate outputs and proofs as before
    let outputs: Vec<_> = witnesses
        .iter()
        .map(|witness| vrf.evaluate(witness).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| vrf.prove_with_challenge(&witnesses[i], &outputs[i], &challenges[i], &mut rng))
        .collect();

    // Now verification should pass
    group.bench_function("Verify", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                let is_valid = vrf.verify(&pks[i], &outputs[i], &proofs[i], &challenges[i]);
                assert!(is_valid, "P-DY-Priv-VRF verification failed");
            }
        })
    });

    group.finish();
}

fn bench_p_dy_priv_extra_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("p_dy_priv_extra");
    let mut rng = test_rng();

    // Initialize VRF
    let vrf = PDYPrivExtraVRF::<G1Affine>::new(&mut rng);

    // Generate secret key
    let sk = Fr::rand(&mut rng);

    // Pre-compute challenges for consistent testing
    let challenges: Vec<_> = (0..NUM_RUNS).map(|_| Fr::rand(&mut rng)).collect();

    // Benchmark eval_prove
    group.bench_function("eval_prove", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                // Generate random input
                let x = Fr::rand(&mut rng);

                // Generate full witness
                let witness = vrf.generate_full_witness(&sk, &x, &mut rng);

                // Evaluate VRF and create commitments
                let output = vrf.evaluate(&witness).expect("Failed to evaluate VRF");

                // Generate proof
                let _proof = vrf.prove_with_challenge(&witness, &output, &challenges[i], &mut rng);
            }
        })
    });

    // Pre-compute witnesses, outputs, and proofs for verification
    let witnesses: Vec<_> = (0..NUM_RUNS)
        .map(|_| {
            let x = Fr::rand(&mut rng);
            vrf.generate_full_witness(&sk, &x, &mut rng)
        })
        .collect();

    let outputs: Vec<_> = witnesses
        .iter()
        .map(|witness| vrf.evaluate(witness).expect("Failed to evaluate VRF"))
        .collect();

    let proofs: Vec<_> = (0..NUM_RUNS)
        .map(|i| vrf.prove_with_challenge(&witnesses[i], &outputs[i], &challenges[i], &mut rng))
        .collect();

    // Benchmark verify
    group.bench_function("verify", |b| {
        b.iter(|| {
            for i in 0..NUM_RUNS {
                let is_valid = vrf.verify(
                    &outputs[i].commitments,
                    &outputs[i].y,
                    &proofs[i],
                    &challenges[i],
                );
                assert!(is_valid, "P-DY-Priv-Extra-VRF verification failed");
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dy_vrf,
    bench_p_dy_vrf,
    bench_p_dy_priv_vrf,
    bench_p_dy_priv_extra_vrf
);
criterion_main!(benches);
