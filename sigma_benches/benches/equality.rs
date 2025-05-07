// sigma_equality.rs
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use ark_std::{rand::Rng, test_rng};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

pub mod equality_protocol {
    use super::*;

    pub struct Statement {
        // Committed values C1 = g1^x * h1^r1, C2 = g2^x * h2^r2
        pub c1: G1Affine,
        pub c2: G1Affine,
        pub g1: G1Affine,
        pub h1: G1Affine,
        pub g2: G1Affine,
        pub h2: G1Affine,
    }

    pub struct Witness {
        pub x: Fr,  // The common value
        pub r1: Fr, // First randomness
        pub r2: Fr, // Second randomness
    }

    pub struct Commitment {
        pub a1: G1Affine,
        pub a2: G1Affine,
    }

    pub struct Proof {
        pub z_x: Fr,
        pub z_r1: Fr,
        pub z_r2: Fr,
    }

    pub fn commit(statement: &Statement, rng: &mut impl Rng) -> (Commitment, Fr, Fr, Fr) {
        // Choose random blinding factors
        let alpha = Fr::rand(rng);
        let rho1 = Fr::rand(rng);
        let rho2 = Fr::rand(rng);

        // Compute commitments
        let a1 = (statement.g1.mul(alpha) + statement.h1.mul(rho1)).into_affine();
        let a2 = (statement.g2.mul(alpha) + statement.h2.mul(rho2)).into_affine();

        (Commitment { a1, a2 }, alpha, rho1, rho2)
    }

    pub fn prove(alpha: &Fr, rho1: &Fr, rho2: &Fr, witness: &Witness, challenge: &Fr) -> Proof {
        // Compute responses
        let z_x = alpha + &(challenge * &witness.x);
        let z_r1 = rho1 + &(challenge * &witness.r1);
        let z_r2 = rho2 + &(challenge * &witness.r2);

        Proof { z_x, z_r1, z_r2 }
    }

    pub fn verify(
        statement: &Statement,
        commitment: &Commitment,
        proof: &Proof,
        challenge: &Fr,
    ) -> bool {
        // Verify first equation: a1 + c*C1 = g1^z_x * h1^z_r1
        let lhs1 = (commitment.a1.into_group() + statement.c1.mul(*challenge)).into_affine();
        let rhs1 = (statement.g1.mul(proof.z_x) + statement.h1.mul(proof.z_r1)).into_affine();

        // Verify second equation: a2 + c*C2 = g2^z_x * h2^z_r2
        let lhs2 = (commitment.a2.into_group() + statement.c2.mul(*challenge)).into_affine();
        let rhs2 = (statement.g2.mul(proof.z_x) + statement.h2.mul(proof.z_r2)).into_affine();

        lhs1 == rhs1 && lhs2 == rhs2
    }

    pub fn execute_protocol(statement: &Statement, witness: &Witness, rng: &mut impl Rng) -> bool {
        let (commitment, alpha, rho1, rho2) = commit(statement, rng);
        let challenge = Fr::rand(rng);
        let proof = prove(&alpha, &rho1, &rho2, witness, &challenge);
        verify(statement, &commitment, &proof, &challenge)
    }
}

// Setup function for test parameters
fn setup_equality_test() -> (equality_protocol::Statement, equality_protocol::Witness) {
    let mut rng = test_rng();

    // Generate bases
    let g1 = G1Affine::rand(&mut rng);
    let h1 = G1Affine::rand(&mut rng);
    let g2 = G1Affine::rand(&mut rng);
    let h2 = G1Affine::rand(&mut rng);

    // Generate witness
    let x = Fr::rand(&mut rng);
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);

    // Compute commitments
    let c1 = (g1.mul(x) + h1.mul(r1)).into_affine();
    let c2 = (g2.mul(x) + h2.mul(r2)).into_affine();

    let statement = equality_protocol::Statement {
        c1,
        c2,
        g1,
        h1,
        g2,
        h2,
    };
    let witness = equality_protocol::Witness { x, r1, r2 };

    (statement, witness)
}

pub fn benchmark_equality_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("sigma");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(10));

    let (statement, witness) = setup_equality_test();

    group.bench_function(BenchmarkId::new("equality", "standard"), |b| {
        let mut rng = test_rng();
        b.iter(|| equality_protocol::execute_protocol(&statement, &witness, &mut rng))
    });

    group.finish();
}

criterion_group!(benches, benchmark_equality_protocol);
criterion_main!(benches);
