use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ark_ff::{PrimeField, UniformRand};

use ark_std::{
    ops::{Add, Mul, Neg, Sub},
    rand::Rng,
    One, Zero,
};

struct PublicParams<E: Pairing> {
    sig_g1: E::G1Affine,
    sig_g2: E::G2Affine,
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

struct Signature<E: Pairing> {
    sigma1: E::G1Affine,
    sigma2: E::G1Affine,
}

struct Commitment<E: Pairing> {
    com: E::G1Affine,
    t: E::ScalarField,
}

struct SignatureProof<E: Pairing> {
    sigma_prime1: E::G1Affine,
    sigma_prime2: E::G1Affine,
    pi: SchnorrProof<E>,
}

struct SignatureProof<E: Pairing> {
    A: E::G1Affine,
    A_prime: E::G1Affine,
    d: E::ScalarField,
    r: Vec<E::ScalarField>,
}

struct SchnorrProof<E: Pairing> {
    com_prime: E::G1Affine,
    z_t: E::ScalarField,      //for blinding factor
    z_m: Vec<E::ScalarField>, //for messages
}

fn setup<E: Pairing, R: Rng>(rng: &mut R) -> PublicParams<E> {
    PublicParams {
        sig_g1: E::G1::rand(rng).into_affine(),
        sig_g2: E::G2::rand(rng).into_affine(),
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

    let x_g1 = params.sig_g1.mul(x).into_affine();
    let y_g1 = y
        .iter()
        .map(|yi| params.sig_g1.mul(yi).into_affine())
        .collect::<Vec<_>>();

    let x_g2 = params.sig_g2.mul(x).into_affine();
    let y_g2 = y
        .iter()
        .map(|yi| params.sig_g2.mul(yi).into_affine())
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
    let com = params.sig_g1.mul(t)
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

    let com_prime = params.sig_g1.mul(r_t)
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

    let lhs = params.sig_g1.mul(z_t)
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
    let sigma1 = params.sig_g1.mul(u).into_affine();
    let sigma2 = (params.sig_g1.mul(sk.x) + commitment).mul(u).into_affine();
    Signature { sigma1, sigma2 }
}

fn unblind<E: Pairing>(signature: &Signature<E>, t: &E::ScalarField) -> Signature<E> {
    Signature {
        sigma1: signature.sigma1,
        sigma2: (signature.sigma2.into_group() - signature.sigma1.mul(*t)).into_affine(),
    }
}

fn verify_test<E: Pairing>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    messages: &[E::ScalarField],
    signature: &Signature<E>,
) -> bool {
    let lhs = E::pairing(signature.sigma2, params.sig_g2);
    let rhs = E::pairing(signature.sigma1, pk.x_g2)
        * pk.y_g2
            .iter()
            .zip(messages)
            .map(|(Yi, mi)| E::pairing(signature.sigma1, Yi).mul_bigint(mi.into_bigint()))
            .fold(
                E::pairing(E::G1::generator(), E::G2::generator()),
                |acc, x| acc * x,
            );

    lhs == rhs
}

// fn prove_signature_knowledge<>
// ark_ec::pairing::PairingOutput<E>
