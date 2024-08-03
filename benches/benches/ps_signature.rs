// use ark_bls12_381::Fr;
// use ark_ff::UniformRand;
// use ark_std::test_rng;
// use criterion::{black_box, criterion_group, criterion_main, Criterion};
// use ps::{keygen, sign, verify, PublicKey, SecretKey, Signature};

// fn benchmark_keygen(c: &mut Criterion) {
//     let mut group = c.benchmark_group("PS Signature");
//     for attribute_count in [5, 10, 20] {
//         group.bench_function(format!("keygen_{}", attribute_count), |b| {
//             b.iter(|| {
//                 let mut rng = test_rng();
//                 keygen(black_box(&mut rng), black_box(attribute_count))
//             })
//         });
//     }
//     group.finish();
// }

// fn benchmark_sign(c: &mut Criterion) {
//     let mut group = c.benchmark_group("PS Signature");
//     for attribute_count in [5, 10, 20] {
//         group.bench_function(format!("sign_{}", attribute_count), |b| {
//             let mut rng = test_rng();
//             let (sk, _) = keygen(&mut rng, attribute_count);
//             let messages: Vec<Fr> = (0..attribute_count).map(|_| Fr::rand(&mut rng)).collect();
//             b.iter(|| sign(black_box(&sk), black_box(&messages), black_box(&mut rng)))
//         });
//     }
//     group.finish();
// }

// fn benchmark_verify(c: &mut Criterion) {
//     let mut group = c.benchmark_group("PS Signature");
//     for attribute_count in [5, 10, 20] {
//         group.bench_function(format!("verify_{}", attribute_count), |b| {
//             let mut rng = test_rng(); //
//             let (sk, pk) = keygen(&mut rng, attribute_count);
//             let messages: Vec<Fr> = (0..attribute_count).map(|_| Fr::rand(&mut rng)).collect();
//             let signature = sign(&sk, &messages, &mut rng);
//             b.iter(|| verify(black_box(&pk), black_box(&messages), black_box(&signature)))
//         });
//     }
//     group.finish();
// }

// // Add similar functions for sign and verify

// criterion_group!(benches, benchmark_keygen, benchmark_sign, benchmark_verify); // Add other benchmark functions here
// criterion_main!(benches);
