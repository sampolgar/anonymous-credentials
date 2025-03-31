use ark_bls12_381::{Bls12_381, Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::CyclotomicMultSubgroup;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::test_rng;
use ark_std::{
    ops::{Add, AddAssign, Mul, MulAssign, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Instant;

// Constants for benchmark configuration
const SAMPLE_SIZE: usize = 20;
const PAIRING_SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

/// Generates random test data: vectors of points in G1 and G2 with scalars
fn generate_test_data<P: Pairing>(
    n: usize,
) -> (Vec<P::G1Affine>, Vec<P::G2Affine>, Vec<P::ScalarField>) {
    let mut rng = test_rng();
    let a: Vec<P::G1Affine> = (0..n).map(|_| P::G1Affine::rand(&mut rng)).collect();
    let b: Vec<P::G2Affine> = (0..n).map(|_| P::G2Affine::rand(&mut rng)).collect();
    let scalars: Vec<P::ScalarField> = (0..n).map(|_| P::ScalarField::rand(&mut rng)).collect();
    (a, b, scalars)
}

/// Method 1: Computes the product of pairings by calculating each pairing fully and multiplying in GT.
fn compute_product_full_pairings<P: Pairing>(
    a: &[P::G1Affine],
    b: &[P::G2Affine],
) -> P::TargetField {
    let mut product = P::TargetField::one();
    for (ai, bi) in a.iter().zip(b.iter()) {
        let pairing = P::pairing(*ai, *bi);
        product.add_assign(pairing.0);
    }
    product
}

/// Method 2: Computes the product of pairings using a single multi-Miller loop and one final exponentiation.
fn compute_product_multi_miller<P: Pairing>(
    a: &[P::G1Affine],
    b: &[P::G2Affine],
) -> P::TargetField {
    let a_prep: Vec<P::G1Prepared> = a.iter().map(|x| P::G1Prepared::from(*x)).collect();
    let b_prep: Vec<P::G2Prepared> = b.iter().map(|x| P::G2Prepared::from(*x)).collect();

    let ml = P::multi_miller_loop(a_prep.into_iter(), b_prep.into_iter());
    P::final_exponentiation(ml).unwrap().0
}

/// Method 4: Scale G1 points with scalars, then do the pairing
fn compute_with_scaled_g1<P: Pairing>(
    g1_points: &[P::G1Affine],
    g2_points: &[P::G2Affine],
    scalars: &[P::ScalarField],
) -> P::TargetField {
    // Scale each g1 point by a scalar
    let scaled_g1_projective: Vec<P::G1> = g1_points
        .iter()
        .zip(scalars.iter())
        .map(|(g1, s)| g1.into_group().mul(s))
        .collect();

    let scaled_g1_affine: Vec<P::G1Affine> = P::G1::normalize_batch(&scaled_g1_projective);

    // Then compute the multi-pairing
    let prepared_g1: Vec<_> = scaled_g1_affine.iter().map(P::G1Prepared::from).collect();
    let prepared_g2: Vec<_> = g2_points.iter().map(P::G2Prepared::from).collect();

    P::multi_pairing(prepared_g1, prepared_g2).0
}

/// Benchmark function comparing the pairing methods
fn bench_pairing_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("pairing");
    group.sample_size(SAMPLE_SIZE);

    for &n in PAIRING_SIZES.iter() {
        group.throughput(Throughput::Elements(n as u64));
        let (a, b, scalars) = generate_test_data::<Bls12_381>(n);

        // Benchmark Method 1: Individual pairings and then product in GT
        group.bench_with_input(
            BenchmarkId::new("full_pairings", n),
            &(a.clone(), b.clone()),
            |bench, (a, b)| {
                bench.iter(|| {
                    let product =
                        compute_product_full_pairings::<Bls12_381>(black_box(a), black_box(b));
                    black_box(product)
                })
            },
        );

        // Benchmark Method 3: Scaled multi_pairing
        group.bench_with_input(
            BenchmarkId::new("multi_miller", n),
            &(a.clone(), b.clone(), scalars.clone()),
            |bench, (a, b, scalars)| {
                bench.iter(|| {
                    let product = compute_with_scaled_g1::<Bls12_381>(
                        black_box(a),
                        black_box(b),
                        black_box(scalars),
                    );
                    black_box(product)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pairing_product);
criterion_main!(benches);

// use ark_bls12_381::{Bls12_381, Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
// use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
// use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
// use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
// use ark_ff::CyclotomicMultSubgroup;
// use ark_ff::{Field, PrimeField, UniformRand};
// use ark_r1cs_std::uint;
// use ark_std::test_rng;
// use ark_std::{
//     ops::{Add, AddAssign, Mul, MulAssign, Neg},
//     rand::Rng,
//     sync::Mutex,
//     One, Zero,
// };
// use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
// use std::time::Instant;

// // Constants for benchmark configuration
// const SAMPLE_SIZE: usize = 10;
// const PAIRING_SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

// /// Generates random test data: vectors of points in G1 and G2 with scalars
// fn generate_test_data<P: Pairing>(
//     n: usize,
// ) -> (Vec<P::G1Affine>, Vec<P::G2Affine>, Vec<P::ScalarField>) {
//     let mut rng = test_rng();
//     let a: Vec<P::G1Affine> = (0..n).map(|_| P::G1Affine::rand(&mut rng)).collect();
//     let b: Vec<P::G2Affine> = (0..n).map(|_| P::G2Affine::rand(&mut rng)).collect();
//     let scalars: Vec<P::ScalarField> = (0..n).map(|_| P::ScalarField::rand(&mut rng)).collect();
//     (a, b, scalars)
// }

// /// Method 1: Computes the product of pairings by calculating each pairing fully and multiplying in GT.
// fn compute_product_full_pairings<P: Pairing>(
//     a: &[P::G1Affine],
//     b: &[P::G2Affine],
// ) -> P::TargetField {
//     let mut product = P::TargetField::one();
//     for (ai, bi) in a.iter().zip(b.iter()) {
//         let pairing = P::pairing(*ai, *bi);
//         product.add_assign(pairing);
//     }
//     product
// }

// /// Method 2: Computes the product of pairings using a single multi-Miller loop and one final exponentiation.
// fn compute_product_multi_miller<P: Pairing>(
//     a: &[P::G1Affine],
//     b: &[P::G2Affine],
// ) -> P::TargetField {
//     let a_prep: Vec<P::G1Prepared> = a.iter().map(|x| P::G1Prepared::from(*x)).collect();
//     let b_prep: Vec<P::G2Prepared> = b.iter().map(|x| P::G2Prepared::from(*x)).collect();

//     let ml = P::multi_miller_loop(a_prep.into_iter(), b_prep.into_iter());
//     P::final_exponentiation(ml).unwrap().0
// }

// /// Method 4: Scale G1 points with scalars, then do the pairing
// fn compute_with_scaled_g1<P: Pairing>(
//     g1_points: &[P::G1Affine],
//     g2_points: &[P::G2Affine],
//     scalars: &[P::ScalarField],
// ) -> P::TargetField {
//     // Scale each g1 point by a scalar
//     let scaled_g1_projective: Vec<P::G1> = g1_points
//         .iter()
//         .zip(scalars.iter())
//         .map(|(g1, s)| g1.into_group().mul(s))
//         .collect();

//     let scaled_g1_affine: Vec<P::G1Affine> = E::G1::normalize_batch(&scaled_g1_projective);

//     // Then compute the multi-pairing
//     let prepared_g1: Vec<_> = scaled_g1_affine.iter().map(P::G1Prepared::from).collect();
//     let prepared_g2: Vec<_> = g2_points.iter().map(P::G2Prepared::from).collect();

//     P::multi_pairing(prepared_g1, prepared_g2)
// }

// /// Benchmark function comparing the pairing methods
// fn bench_pairing_product(c: &mut Criterion) {
//     let mut group = c.benchmark_group("pairing_product");
//     group.sample_size(SAMPLE_SIZE);

//     for &n in PAIRING_SIZES.iter() {
//         group.throughput(Throughput::Elements(n as u64));
//         let (a, b, scalars) = generate_test_data::<Bls12_381>(n);

//         // Benchmark Method 1: Individual pairings and then product in GT
//         group.bench_with_input(
//             BenchmarkId::new("full_pairings", n),
//             &(a.clone(), b.clone()),
//             |bench, (a, b)| {
//                 bench.iter(|| {
//                     let product =
//                         compute_product_full_pairings::<Bls12_381>(black_box(a), black_box(b));
//                     black_box(product)
//                 })
//             },
//         );

//         // Benchmark Method 2: Multi-Miller loop
//         group.bench_with_input(
//             BenchmarkId::new("multi_miller", n),
//             &(a.clone(), b.clone()),
//             |bench, (a, b)| {
//                 bench.iter(|| {
//                     let product =
//                         compute_product_multi_miller::<Bls12_381>(black_box(a), black_box(b));
//                     black_box(product)
//                 })
//             },
//         );

//         // Benchmark Method 3: Scaled multi_pairing
//         group.bench_with_input(
//             BenchmarkId::new("scaled_g1_pairing", n),
//             &(a.clone(), b.clone(), scalars.clone()),
//             |bench, (a, b, scalars)| {
//                 bench.iter(|| {
//                     let product = compute_with_scaled_g1::<Bls12_381>(
//                         black_box(a),
//                         black_box(b),
//                         black_box(scalars),
//                     );
//                     black_box(product)
//                 })
//             },
//         );
//     }

//     group.finish();
// }

// criterion_group!(benches, bench_pairing_product);
// criterion_main!(benches);
