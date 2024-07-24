use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;
use crate::pairing::PairingCheck;

use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
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

// TODO - change this to commitment key in g1 and g2, more simple
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

fn generate_signature_of_knowledge<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    pk: &PublicKey<E>,
    signature: &Signature<E>,
    messages: &[E::ScalarField],
    challenge: &E::ScalarField,
    rng: &mut R,
) -> SignatureProof<E> {
    // e(sigma_1', x_g2) * ∑ e(sigma_1', y_i) * e(sigma1', g2)^t = e(sigma_2', g2)

    // ∑ e(sigma_1', y_i)^m_i * e(sigma1', g2)^t  = e(sigma_2', g2) - e(sigma_1', x_g2)

    // commit to m_i and t as G1 elements.
    // e(sigma_1', g2)^beta => sigma1'*beta
    // e(sigma1', y_i)^m_i => sigma1' * Y_i
    // commit to m_i and t as GT elements. similar to schnorr prior protocol, the bases are 
    // 1 e(sigma_1', g2) for beta 
    // 2i e(sigma_1', y_i) for each alpha_i
    // commitment_prime is T = one GT point composed of 1, 2i = e(sigma_1', g2)^beta * e(sigma_1', y_i)^mi


    
    // responses
    // z_t = beta + challenge * t
    // z_i = alpha_i + challenge * m_i
    
    // proofs sent are z_t, z_i, sigma', com_prime
    // verifier does base_1^z_t * base_i^z_i = sigma'^challenge * T
}


#[cfg(test)]
use super::*;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_std::test_rng;

#[test]
fn test_setup() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    assert!(!params.generator_g1.is_zero());
    assert!(!params.generator_g2.is_zero());
}

#[test]
fn test_commit_and_prove_knowledge() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    let num_messages = 2;
    let (sk, pk) = keygen(&params, &mut rng, num_messages);

    // create messages
    let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let mut messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..num_messages)
        .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
        .collect();
    messages.insert(0, t);

    let mut bases = pk.y_g1.clone();
    bases.insert(0, params.generator_g1);

    // generate commitment to messages
    let com = G1Projective::msm_unchecked(&bases, &messages).into_affine();
    
    let challenge = Fr::rand(&mut rng); // In practice, this should be derived from a hash
    
    // generate commitment for proving
    let com_prime = SchnorrProtocol::commit(&bases, &mut rng);
    let response = SchnorrProtocol::prove(&com_prime, &messages, &challenge);
    let is_valid = SchnorrProtocol::verify(&bases, &com, &com_prime, &response, &challenge);

    assert!(is_valid, "Schnorr proof verification failed");
}

fn test_pairing_verification() {}
