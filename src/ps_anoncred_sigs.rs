use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;

use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand};

use ark_std::{
    ops::{Add, Mul, MulAssign, Neg, Sub},
    rand::Rng,
    One, Zero,
};

struct PublicParams<E: Pairing> {
    generator_g1: E::G1Affine,
    generator_g2: E::G2Affine,
}

struct SecretKey<F: PrimeField> {
    x: F,
    y: Vec<F>,
}

struct PublicKey<E: Pairing> {
    x_g1: E::G1Affine,
    y_g1: Vec<E::G1Affine>,
    x_g2: E::G2Affine,
    y_g2: Vec<E::G2Affine>,
}

#[derive(Debug)]
struct Signature<E: Pairing> {
    sigma1: E::G1Affine,
    sigma2: E::G1Affine,
}

struct Commitment<E: Pairing> {
    com: E::G1Affine,
    t: E::ScalarField,
}
#[derive(Debug)]
pub struct SignatureProof<E: Pairing> {
    sigma1_prime: E::G1Affine,
    sigma2_prime: E::G1Affine,
    com_t: E::TargetField,
    z_t: E::ScalarField,
    z_i: Vec<E::ScalarField>,
}

#[derive(Debug)]
struct SchnorrProof<E: Pairing> {
    com_prime: E::G1Affine,
    z_t: E::ScalarField,      //for blinding factor
    z_m: Vec<E::ScalarField>, //for messages
}

fn setup<E: Pairing, R: Rng>(rng: &mut R) -> PublicParams<E> {
    PublicParams {
        generator_g1: E::G1::rand(rng).into_affine(),
        generator_g2: E::G2::rand(rng).into_affine(),
    }
}

fn keygen<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    rng: &mut R,
    message_count: usize,
) -> (SecretKey<E::ScalarField>, PublicKey<E>) {
    let x = E::ScalarField::rand(rng);
    let y = (0..message_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = params.generator_g1.mul(x).into_affine();
    let y_g1 = y
        .iter()
        .map(|yi| params.generator_g1.mul(yi).into_affine())
        .collect::<Vec<_>>();

    let x_g2 = params.generator_g2.mul(x).into_affine();
    let y_g2 = y
        .iter()
        .map(|yi| params.generator_g2.mul(yi).into_affine())
        .collect::<Vec<_>>();

    (
        SecretKey { x, y },
        PublicKey {
            x_g1,
            y_g1,
            x_g2,
            y_g2,
        },
    )
}

fn commit<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    messages: &[E::ScalarField],
    rng: &mut R,
) -> Commitment<E> {
    let t = E::ScalarField::rand(rng);
    let com = params.generator_g1.mul(t)
        + pk.y_g1
            .iter()
            .zip(messages)
            .map(|(Yi, mi)| Yi.mul(*mi))
            .sum::<E::G1>();
    Commitment {
        com: com.into_affine(),
        t,
    }
}

fn prove_knowledge<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    commitment: &Commitment<E>,
    messages: &[E::ScalarField],
    rng: &mut R,
) -> SchnorrProof<E> {
    // t_prime blinds t e.g. z1 = t_prime + e*t.
    let r_t = E::ScalarField::rand(rng);
    let r_m: Vec<E::ScalarField> = (0..messages.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect();
    // we aren't measuring proof gen time so we just use the same hash value
    let e = E::ScalarField::rand(rng);

    let com_prime = params.generator_g1.mul(r_t)
        + pk.y_g1
            .iter()
            .zip(&r_m)
            .map(|(Yi, ri)| Yi.mul(*ri))
            .sum::<E::G1>();

    let z_t = r_t + e * commitment.t;
    let z_m: Vec<E::ScalarField> = r_m
        .iter()
        .zip(messages)
        .map(|(ri, mi)| *ri + e * mi)
        .collect();

    SchnorrProof {
        com_prime: com_prime.into_affine(),
        z_t,
        z_m,
    }
}

fn verify_proof<E: Pairing>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    commitment: &Commitment<E>,
    proof: &SchnorrProof<E>,
    e: &E::ScalarField,
) -> bool {
    let com_prime = proof.com_prime;
    let z_t = proof.z_t;
    let z_m = &proof.z_m;

    let lhs = params.generator_g1.mul(z_t)
        + pk.y_g1
            .iter()
            .zip(z_m)
            .map(|(Yi, zi)| Yi.mul(*zi))
            .sum::<E::G1>();

    let rhs = commitment.com.mul(*e) + com_prime;

    lhs.into_affine() == rhs.into_affine()
}

fn sign<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    sk: &SecretKey<E::ScalarField>,
    commitment: &E::G1Affine,
    rng: &mut R,
) -> Signature<E> {
    let u = E::ScalarField::rand(rng);
    let sigma1 = params.generator_g1.mul(u).into_affine();
    let sigma2 = (params.generator_g1.mul(sk.x) + commitment)
        .mul(u)
        .into_affine();
    Signature { sigma1, sigma2 }
}

fn unblind<E: Pairing>(signature: &Signature<E>, t: &E::ScalarField) -> Signature<E> {
    Signature {
        sigma1: signature.sigma1,
        sigma2: (signature.sigma2.into_group() - signature.sigma1.mul(*t)).into_affine(),
    }
}

fn prove_signature_knowledge<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    signature: &Signature<E>,
    messages: &[E::ScalarField],
    challenge: &E::ScalarField,
    rng: &mut R,
) -> SignatureProof<E> {
    let r = E::ScalarField::rand(rng);
    let t = E::ScalarField::rand(rng);
    let sigma1_prime = signature.sigma1.mul(r).into_affine();
    let sigma2_prime = (signature.sigma2.mul(r) - params.generator_g1.mul(r * t)).into_affine();

    let beta = E::ScalarField::rand(rng);
    let alpha_i: Vec<E::ScalarField> = (0..messages.len())
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    let mut com_t = E::pairing(sigma1_prime.mul(beta).into_affine(), params.generator_g2);
    for (alpha_i, y_i) in alpha_i.iter().zip(pk.y_g2.iter()) {
        com_t += E::pairing(sigma1_prime.mul(*alpha_i).into_affine(), *y_i);
    }

    // let challenge = E::ScalarField::rand(rng);
    let z_t = beta + challenge.mul(t);
    let z_i: Vec<E::ScalarField> = alpha_i
        .iter()
        .zip(messages)
        .map(|(alpha_i, mi)| *alpha_i + challenge.mul(mi))
        .collect();

    println!("Proof generation:");
    println!("  r: {:?}", r);
    println!("  t: {:?}", t);
    println!("  beta: {:?}", beta);
    println!("  alpha_i: {:?}", alpha_i);
    println!("  challenge: {:?}", challenge);
    println!("  z_t: {:?}", z_t);
    println!("  z_i: {:?}", z_i);

    SignatureProof {
        sigma1_prime,
        sigma2_prime,
        com_t: com_t.0,
        z_t,
        z_i,
    }
}

// fn prove_signature_knowledge<E: Pairing, R: Rng>(
//     params: &PublicParams<E>,
//     pk: &PublicKey<E>,
//     signature: &Signature<E>,
//     messages: &[E::ScalarField],
//     rng: &mut R,
// ) -> SignatureProof<E> {
//     // prover generates sigma_prime: σ' = (σ'₁, σ'₂) = (sigma1^r, (sigma_2 * sigma_1^t)^r)
//     let r = E::ScalarField::rand(rng);
//     let t = E::ScalarField::rand(rng);
//     let sigma1_prime = signature.sigma1.mul(r).into_affine();
//     let sigma2_prime = (signature.sigma2.mul(r) - params.generator_g1.mul(r * t)).into_affine();

//     // conduct PoK for (m_1,...,m_i, t). z1 = beta + e * t, z2 = alpha_i + e * m_i. Generate random values for T
//     let beta = E::ScalarField::rand(rng);
//     let alpha_i: Vec<E::ScalarField> = (0..messages.len())
//         .map(|_| E::ScalarField::rand(rng))
//         .collect();

//     // let mut t = E::pairing(sigma1_prime, params.generator_g2).mul_assign(beta);
//     let mut com_t = E::pairing(sigma1_prime.mul(beta).into_affine(), params.generator_g2);
//     for (alpha_i, y_i) in alpha_i.iter().zip(pk.y_g2.iter()) {
//         com_t += E::pairing(sigma1_prime.mul(*alpha_i).into_affine(), *y_i);
//     }

//     let challenge = E::ScalarField::rand(rng);

//     let z_t = beta + challenge * t;
//     let z_i: Vec<E::ScalarField> = alpha_i
//         .iter()
//         .zip(messages)
//         .map(|(alpha_i, mi)| *alpha_i + challenge * mi)
//         .collect();

//     SignatureProof {
//         sigma1_prime,
//         sigma2_prime,
//         com_t: com_t.0, // assuming TargetField is the type of the pairing result
//         z_t,
//         z_i,
//     }
// }

// pub fn verify_signature_proof<E: Pairing>(
//     params: &PublicParams<E>,
//     pk: &PublicKey<E>,
//     proof: &SignatureProof<E>,
//     challenge: &E::ScalarField,
// ) -> bool {
//     // compute com_t * (e(sigma2_prime, generator_g2) / e(sigma1_prime, params.x_g2))))
//     let lhs = E::pairing(proof.sigma2_prime, params.generator_g2)
//         - E::pairing(proof.sigma1_prime, pk.x_g2);
//     let lhs = lhs.mul(challenge);
//     let lhs = E::TargetField::from(proof.com_t) + lhs.0;

//     // compute rhs verification
//     let mut rhs = E::pairing(
//         proof.sigma1_prime.mul(proof.z_t).into_affine(),
//         params.generator_g2,
//     );
//     for (z_i, y_i) in proof.z_i.iter().zip(pk.y_g2.iter()) {
//         rhs += E::pairing(proof.sigma1_prime.mul(*z_i).into_affine(), *y_i);
//     }
//     lhs == rhs.0
// }

pub fn verify_signature_proof<E: Pairing>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    proof: &SignatureProof<E>,
    challenge: &E::ScalarField,
) -> bool {
    // Compute LHS
    let lhs_1 = E::pairing(proof.sigma2_prime, params.generator_g2);
    let lhs_2 = E::pairing(proof.sigma1_prime, pk.x_g2);
    let lhs_3 = (lhs_1 - lhs_2).mul(*challenge);
    let lhs = proof.com_t + lhs_3.0;

    // Compute RHS
    let mut rhs_1 = E::pairing(
        proof.sigma1_prime.mul(proof.z_t).into_affine(),
        params.generator_g2,
    );
    // let mut rhs_e = E::pairing::PairingOutput::zero();
    let mut rhs_2 = PairingOutput::zero();

    for (i, (z_i, y_i)) in proof.z_i.iter().zip(pk.y_g2.iter()).enumerate() {
        let term = E::pairing(proof.sigma1_prime.mul(*z_i).into_affine(), *y_i);
        rhs_2 += term;
        println!("  Term {}: {:?}", i, term);
    }

    let rhs = rhs_1 + rhs_2;

    println!("Verification:");
    println!("LHS components:");
    println!("  lhs_1: {:?}", lhs_1);
    println!("  lhs_2: {:?}", lhs_2);
    println!("  lhs_3: {:?}", lhs_3);
    println!("  proof.com_t: {:?}", proof.com_t);
    println!("  Final LHS: {:?}", lhs);
    println!("RHS components:");
    println!("  rhs_1: {:?}", rhs_1);
    println!("  rhs_2: {:?}", rhs_2);
    println!("  Final RHS: {:?}", rhs.0);

    lhs == rhs.0
}

#[cfg(test)]
use super::*;
use ark_bls12_381::Bls12_381;
use ark_std::test_rng;

#[test]
fn test_setup() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    assert!(!params.generator_g1.is_zero());
    assert!(!params.generator_g2.is_zero());
}

#[test]
fn test_commit() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    let (_, pk) = keygen(&params, &mut rng, 3);

    let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = vec![
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
    ];

    let commitment = commit(&params, &pk, &messages, &mut rng);
    assert!(!commitment.com.is_zero());
}

#[test]
fn test_sign_and_unblind() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    let (sk, _) = keygen(&params, &mut rng, 3);

    let commitment = <Bls12_381 as Pairing>::G1::rand(&mut rng).into_affine();
    let signature = sign(&params, &sk, &commitment, &mut rng);

    let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let unblinded_signature = unblind(&signature, &t);

    assert_ne!(signature.sigma2, unblinded_signature.sigma2);
    assert_eq!(signature.sigma1, unblinded_signature.sigma1);
}

#[test]
fn test_prove_and_verify_signature_knowledge() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    let (sk, pk) = keygen(&params, &mut rng, 3);

    let messages: Vec<<Bls12_381 as Pairing>::ScalarField> = vec![
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
        <Bls12_381 as Pairing>::ScalarField::rand(&mut rng),
    ];

    let commitment = commit(&params, &pk, &messages, &mut rng);
    let signature = sign(&params, &sk, &commitment.com, &mut rng);
    let unblinded_signature = unblind(&signature, &commitment.t);

    let challenge = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);

    let proof = prove_signature_knowledge(
        &params,
        &pk,
        &unblinded_signature,
        &messages,
        &challenge,
        &mut rng,
    );

    println!("Test computation:");
    println!("Messages: {:?}", messages);
    println!("Signature: {:?}", signature);
    println!("Unblinded Signature: {:?}", unblinded_signature);
    println!("Proof: {:?}", proof);
    println!("Challenge: {:?}", challenge);

    let result = verify_signature_proof(&params, &pk, &proof, &challenge);
    assert!(result, "Signature proof verification failed");
}
