use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ps::psproofs::PSProofs;
use ps::test_helpers::create_ps_test_setup;

fn benchmark_multi_attribute(c: &mut Criterion) {
    println!("Starting multi_attribute benchmark");
    let setup = create_ps_test_setup::<Bls12_381>(6);
    c.bench_function("multi_attribute", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_knowledge(&setup);
            assert!(PSProofs::verify_knowledge(&setup, &proof));
        })
    });
}

fn benchmark_selective_disclosure(c: &mut Criterion) {
    let setup = create_ps_test_setup::<Bls12_381>(5);
    let disclosed_indices = vec![1, 3];
    c.bench_function("selective_disclosure", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_selective_disclosure(&setup, &disclosed_indices).unwrap();
            assert!(PSProofs::verify_selective_disclosure(&setup, &proof).unwrap());
        })
    });
}

fn benchmark_equality_proof(c: &mut Criterion) {
    let setup = create_ps_test_setup::<Bls12_381>(5);
    let equality_checks = vec![(1, setup.messages[1]), (3, setup.messages[3])];
    c.bench_function("equality_proof", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_equality(&setup, &equality_checks).unwrap();
            assert!(PSProofs::verify_equality(&setup, &proof, &equality_checks).unwrap());
        })
    });
}

fn benchmark_equality_proof_10_messages(c: &mut Criterion) {
    let setup = create_ps_test_setup::<Bls12_381>(10);
    let equality_checks = vec![(1, setup.messages[1]), (3, setup.messages[3])];
    c.bench_function("equality_proof_10_messages", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_equality(&setup, &equality_checks).unwrap();
            assert!(PSProofs::verify_equality(&setup, &proof, &equality_checks).unwrap());
        })
    });
}

fn benchmark_equality_proof_20_messages(c: &mut Criterion) {
    let setup = create_ps_test_setup::<Bls12_381>(20);
    let equality_checks = vec![
        (1, setup.messages[1]),
        (3, setup.messages[3]),
        (5, setup.messages[5]),
        (7, setup.messages[7]),
        (9, setup.messages[9]),
    ];
    c.bench_function("equality_proof_20_messages", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_equality(&setup, &equality_checks).unwrap();
            assert!(PSProofs::verify_equality(&setup, &proof, &equality_checks).unwrap());
        })
    });
}

fn benchmark_equality_proof_50_messages(c: &mut Criterion) {
    let setup = create_ps_test_setup::<Bls12_381>(50);
    let equality_checks = vec![
        (1, setup.messages[1]),
        (3, setup.messages[3]),
        (5, setup.messages[5]),
        (7, setup.messages[7]),
        (9, setup.messages[9]),
        (11, setup.messages[11]),
        (13, setup.messages[13]),
        (15, setup.messages[15]),
        (17, setup.messages[17]),
        (19, setup.messages[19]),
    ];
    c.bench_function("equality_proof_50_messages", |b| {
        b.iter(|| {
            let proof = PSProofs::prove_equality(&setup, &equality_checks).unwrap();
            assert!(PSProofs::verify_equality(&setup, &proof, &equality_checks).unwrap());
        })
    });
}

criterion_group!(
    benches,
    benchmark_multi_attribute,
    benchmark_selective_disclosure,
    benchmark_equality_proof,
    benchmark_equality_proof_10_messages,
    benchmark_equality_proof_20_messages,
    benchmark_equality_proof_50_messages
);
criterion_main!(benches);
