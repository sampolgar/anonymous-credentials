use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_std::ops::{Mul, Neg};
use ark_std::rand::Rng;
use ark_std::test_rng;
use ark_std::Zero;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// Constants for benchmark configuration
const SAMPLE_SIZE: usize = 10;
const PAIRING_SIZES: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];

/// Generates random test data: vectors of points in G1 and G2.
fn generate_test_data<P: Pairing>(n: usize) -> (Vec<P::G1Affine>, Vec<P::G2Affine>) {
    let mut rng = test_rng();
    let a: Vec<P::G1Affine> = (0..n).map(|_| P::G1Affine::rand(&mut rng)).collect();
    let b: Vec<P::G2Affine> = (0..n).map(|_| P::G2Affine::rand(&mut rng)).collect();
    (a, b)
}

/// Computes the product of pairings by calculating each pairing fully and multiplying in GT.
fn compute_product_full_pairings<P: Pairing>(
    a: &[P::G1Affine],
    b: &[P::G2Affine],
) -> P::TargetField {
    let mut product = P::TargetField::one();
    for (ai, bi) in a.iter().zip(b.iter()) {
        let pairing = P::pairing(*ai, *bi);
        product *= pairing;
    }
    product
}

/// Computes the product of pairings using a single multi-Miller loop and one final exponentiation.
fn compute_product_multi_miller<P: Pairing>(
    a: &[P::G1Affine],
    b: &[P::G2Affine],
) -> P::TargetField {
    let a_prep: Vec<P::G1Prepared> = a.iter().map(|x| P::G1Prepared::from(*x)).collect();
    let b_prep: Vec<P::G2Prepared> = b.iter().map(|x| P::G2Prepared::from(*x)).collect();
    let ml = P::multi_miller_loop(a_prep.into_iter(), b_prep.into_iter());
    let final_exp = P::final_exponentiation(ml).unwrap();
    assert!(final_exp.is_zero());
    final_exp
    // P::final_exponentiation(ml).unwrap()
}

/// Benchmark function comparing the two methods.
fn bench_pairing_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("pairing_product");
    group.sample_size(SAMPLE_SIZE);

    for &n in PAIRING_SIZES.iter() {
        group.throughput(Throughput::Elements(n as u64));
        let (a, b) = generate_test_data::<Bls12_381>(n);

        // Benchmark full pairings method
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

        // Benchmark multi-Miller loop method
        group.bench_with_input(
            BenchmarkId::new("multi_miller", n),
            &(a.clone(), b.clone()),
            |bench, (a, b)| {
                bench.iter(|| {
                    let product =
                        compute_product_multi_miller::<Bls12_381>(black_box(a), black_box(b));
                    black_box(product)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pairing_product);
criterion_main!(benches);
