use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::Zero;
use ark_std::{rand::Rng, test_rng};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

// Naive implementation of commitment without MSM
fn naive_commit<G: AffineRepr, R: Rng>(
    public_generators: &[G],
    rng: &mut R,
) -> SchnorrCommitment<G> {
    // Generate random blindings
    let random_blindings: Vec<G::ScalarField> = (0..public_generators.len())
        .map(|_| G::ScalarField::rand(rng))
        .collect();

    // Compute commitment without MSM
    let mut commited_blindings = G::Group::zero();
    for (base, blinds) in public_generators.iter().zip(random_blindings.iter()) {
        commited_blindings += base.mul(*blinds);
    }

    SchnorrCommitment {
        random_blindings,
        commited_blindings: commited_blindings.into_affine(),
    }
}

// Naive implementation of proving without MSM
fn naive_prove<G: AffineRepr>(
    commitment: &SchnorrCommitment<G>,
    witnesses: &[G::ScalarField],
    challenge: &G::ScalarField,
) -> SchnorrResponses<G> {
    // This is already optimal as it's just scalar operations
    // But including for completeness
    let schnorr_responses: Vec<G::ScalarField> = commitment
        .random_blindings
        .iter()
        .zip(witnesses.iter())
        .map(|(b, w)| *b + (*w * challenge))
        .collect();
    SchnorrResponses(schnorr_responses)
}

// Naive implementation of verification without MSM
fn naive_verify<G: AffineRepr>(
    public_generators: &[G],
    statement: &G,
    schnorr_commitment: &G,
    schnorr_responses: &[G::ScalarField],
    challenge: &G::ScalarField,
) -> bool {
    let mut lhs = G::Group::zero();

    // Calculate each term individually and sum
    for (base, resp) in public_generators.iter().zip(schnorr_responses.iter()) {
        lhs += base.mul(*resp);
    }

    let lhs = lhs.into_affine();
    let rhs = (schnorr_commitment.into_group() + statement.mul(*challenge)).into_affine();

    lhs == rhs
}

// Setup function to create test parameters of various sizes
fn setup_parameters(size: usize) -> (Vec<G1Affine>, Vec<Fr>, G1Affine, Fr) {
    let mut rng = test_rng();

    // Generate random bases and witnesses
    let bases: Vec<G1Affine> = (0..size).map(|_| G1Affine::rand(&mut rng)).collect();
    let witnesses: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

    // Compute statement = g1^w1 * g2^w2 * ... * gn^wn
    // let statement: G = G::Group::msm_unchecked(&bases, &witnesses).into_affine();
    // Compute statement = g1^w1 * g2^w2 * ... * gn^wn
    let statement = ark_bls12_381::G1Projective::msm_unchecked(&bases, &witnesses).into_affine();

    // Random challenge
    let challenge = Fr::rand(&mut rng);

    (bases, witnesses, statement, challenge)
}

// Benchmark commitment generation
fn bench_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_commitment");

    for size in [4, 8, 16, 32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        let (bases, _, _, _) = setup_parameters(*size);

        // MSM-based commitment
        group.bench_with_input(BenchmarkId::new("msm", size), &bases, |b, bases| {
            let mut rng = test_rng();
            b.iter(|| SchnorrProtocol::commit(black_box(bases), &mut rng));
        });

        // Naive commitment (without MSM)
        group.bench_with_input(BenchmarkId::new("naive", size), &bases, |b, bases| {
            let mut rng = test_rng();
            b.iter(|| naive_commit(black_box(bases), &mut rng));
        });
    }

    group.finish();
}

// Benchmark proof generation
fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_prove");

    for size in [4, 8, 16, 32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        let (bases, witnesses, _, challenge) = setup_parameters(*size);
        let mut rng = test_rng();
        let commitment = SchnorrProtocol::commit(&bases, &mut rng);

        // Standard prove (already optimal, but included for completeness)
        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &(commitment.clone(), witnesses.clone(), challenge),
            |b, (commitment, witnesses, challenge)| {
                b.iter(|| {
                    SchnorrProtocol::prove(
                        black_box(commitment),
                        black_box(witnesses),
                        black_box(challenge),
                    )
                });
            },
        );

        // "Naive" prove (identical operation, included for comparison)
        group.bench_with_input(
            BenchmarkId::new("naive", size),
            &(commitment.clone(), witnesses.clone(), challenge),
            |b, (commitment, witnesses, challenge)| {
                b.iter(|| {
                    naive_prove(
                        black_box(commitment),
                        black_box(witnesses),
                        black_box(challenge),
                    )
                });
            },
        );
    }

    group.finish();
}

// Benchmark verification
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_verification");

    for size in [4, 8, 16, 32, 64, 128, 256, 512, 1024].iter() {
        group.throughput(Throughput::Elements(*size as u64));

        let (bases, witnesses, statement, challenge) = setup_parameters(*size);
        let mut rng = test_rng();
        let commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let responses = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        // MSM-based verification
        group.bench_with_input(
            BenchmarkId::new("msm", size),
            &(
                bases.clone(),
                statement,
                commitment.commited_blindings,
                responses.0.clone(),
                challenge,
            ),
            |b, (bases, statement, schnorr_commitment, responses, challenge)| {
                b.iter(|| {
                    SchnorrProtocol::verify_schnorr(
                        black_box(bases),
                        black_box(statement),
                        black_box(schnorr_commitment),
                        black_box(responses),
                        black_box(challenge),
                    )
                });
            },
        );

        // Naive verification (without MSM)
        group.bench_with_input(
            BenchmarkId::new("naive", size),
            &(
                bases.clone(),
                statement,
                commitment.commited_blindings,
                responses.0.clone(),
                challenge,
            ),
            |b, (bases, statement, schnorr_commitment, responses, challenge)| {
                b.iter(|| {
                    naive_verify(
                        black_box(bases),
                        black_box(statement),
                        black_box(schnorr_commitment),
                        black_box(responses),
                        black_box(challenge),
                    )
                });
            },
        );
    }

    group.finish();
}

// Get more accurate scaling by performing multiple measurements with increasing message sizes
fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_scaling");

    // Test with more granular size increments to better observe scaling behavior
    let sizes = [
        4, 8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
    ];

    for size in sizes.iter() {
        group.throughput(Throughput::Elements(*size as u64));

        let (bases, witnesses, statement, challenge) = setup_parameters(*size);
        let mut rng = test_rng();
        let commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let responses = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        // Only benchmark MSM and naive verification for scaling analysis
        // since that's the most interesting operation for complexity analysis

        // MSM verification
        group.bench_with_input(
            BenchmarkId::new("msm", size),
            &(
                bases.clone(),
                statement,
                commitment.commited_blindings,
                responses.0.clone(),
                challenge,
            ),
            |b, (bases, statement, schnorr_commitment, responses, challenge)| {
                b.iter(|| {
                    SchnorrProtocol::verify_schnorr(
                        black_box(bases),
                        black_box(statement),
                        black_box(schnorr_commitment),
                        black_box(responses),
                        black_box(challenge),
                    )
                });
            },
        );

        // For very large sizes, naive operations may be extremely slow
        // Only run naive benchmarks for smaller sizes
        if *size <= 384 {
            group.bench_with_input(
                BenchmarkId::new("naive", size),
                &(
                    bases.clone(),
                    statement,
                    commitment.commited_blindings,
                    responses.0.clone(),
                    challenge,
                ),
                |b, (bases, statement, schnorr_commitment, responses, challenge)| {
                    b.iter(|| {
                        naive_verify(
                            black_box(bases),
                            black_box(statement),
                            black_box(schnorr_commitment),
                            black_box(responses),
                            black_box(challenge),
                        )
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_commitment,
    bench_prove,
    bench_verification,
    bench_scaling
);
criterion_main!(benches);
