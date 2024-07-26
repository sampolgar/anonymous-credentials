use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;
use crate::pairing::PairingCheck;
use crate::pairing_util::PairingTuple;
use ark_bls12_381::{Bls12_381, G2Projective};

use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use itertools::Itertools;

struct SecretKey<E: Pairing> {
    x: E::ScalarField,
    yi: Vec<E::ScalarField>,
    x_g1: E::G1Affine, //X_1 secret key
}

struct PublicKey<E: Pairing> {
    g1: E::G1Affine,
    g2: E::G2Affine,
    y_g1: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    y_g2: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
    x_g2: E::G2Affine,      //X_2 public key
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

#[derive(Clone, Debug)]
struct Signature<E: Pairing> {
    sigma1: E::G1Affine,
    sigma2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    //C \gets g^t \prod_{i=1}^{n} Y_i^{m_i}.
    pub fn prepare_blind_sign(
        messages: &[E::ScalarField],
        t: &E::ScalarField,
        pk: &PublicKey<E>,
    ) -> E::G1Affine
    where
        E: Pairing,
        E::G1: CurveGroup<ScalarField = E::ScalarField>,
    {
        let mut witnesses: Vec<E::ScalarField> = messages.to_vec();
        witnesses.insert(0, *t);
        let commitment: E::G1Affine = E::G1::msm_unchecked(&pk.y_g1, &witnesses).into_affine();
        commitment
    }

    pub fn blind_sign<R: Rng>(
        pk: &PublicKey<E>,
        sk: &SecretKey<E>,
        commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        // sigma_prime \gets (g^u, (g^x + C)^u)
        let u = E::ScalarField::rand(rng);
        let sigma1 = pk.g1.mul(u).into_affine();
        let sigma2 = (pk.g1.mul(sk.x) + commitment).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn unblind(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1,
            sigma2: (self.sigma2.into_group() - self.sigma1.mul(*t)).into_affine(),
        }
    }

    pub fn rerandomize(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(t).into_affine(),
            sigma2: self.sigma2.mul(t).into_affine(),
        }
    }

    pub fn rerandomize_for_pok(&self, r: &E::ScalarField, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: (self.sigma2.into_group() + self.sigma1.mul(*t))
                .mul(r)
                .into_affine(),
        }
    }

    // 4.2 short randomizable signatures. Test multi-message signature
    pub fn public_sign(messages: &[E::ScalarField], sk: &SecretKey<E>, h: &E::G1Affine) -> Self {
        // h ^ (x + yj*mj)
        assert!(messages.len() == sk.yi.len());
        let mut exponent = sk.x;
        for (y, m) in sk.yi.clone().iter().zip(messages.iter()) {
            exponent += *y * m;
        }

        let sigma2 = h.mul(exponent).into_affine();
        Self { sigma1: *h, sigma2 }
    }

    // 4.2 short randomizable signatures. Test multi-message signature pairing verification
    pub fn public_verify(&self, messages: &[E::ScalarField], pk: &PublicKey<E>) -> bool {
        // check sigma1 != G1::zero()
        assert!(!self.sigma1.is_zero());
        assert_eq!(pk.y_g1.len(), messages.len());

        //
        let x_g2 = pk.x_g2.into_group();

        let yi = pk.y_g2.clone();
        let yimi = E::G2::msm(&yi, &messages).unwrap();
        let yimix = yimi + x_g2;

        let mut rng = test_rng();
        let mr = Mutex::new(rng);

        let a = E::G1Prepared::from(self.sigma1);
        let b = E::G2Prepared::from(yimix);

        let sigma2_inv = self.sigma2.into_group().neg();
        let c = E::G1Prepared::from(sigma2_inv);
        let d = E::G2Prepared::from(pk.g2);

        let pairing_miller_loop = E::multi_miller_loop([a, c], [b, d]);
        let result = E::final_exponentiation(pairing_miller_loop).unwrap();
        PairingOutput::is_zero(&result)
    }
}

fn keygen<E: Pairing, R: Rng>(rng: &mut R, message_count: usize) -> (SecretKey<E>, PublicKey<E>) {
    // setup random g points for public key
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    // generate x and y_i for each message
    let x = E::ScalarField::rand(rng);
    let yi = (0..message_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = g1.mul(x).into_affine();
    // let yimi = E::G2::msm(&yi, &messages).unwrap();

    let y_g1 = yi.iter().map(|yi| g1.mul(yi)).collect::<Vec<_>>();
    let y_g1 = E::G1::normalize_batch(&y_g1);

    let x_g2 = g2.mul(x).into_affine();
    let y_g2 = yi.iter().map(|yi| g2.mul(yi)).collect::<Vec<_>>();
    let y_g2 = E::G2::normalize_batch(&y_g2);

    (
        SecretKey { x, yi, x_g1 },
        PublicKey {
            g1,
            g2,
            y_g1,
            y_g2,
            x_g2,
        },
    )
}

#[cfg(test)]
use super::*;
use ark_bls12_381::{Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::bls12::{G1Prepared, G2Prepared};
use ark_std::test_rng;

#[test]
fn test_sign_and_verify() {
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    let (sk, pk) = keygen(&mut rng, message_count);

    // Create messages
    let messages: Vec<Fr> = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let h = G1Affine::rand(&mut rng);
    let public_signature = Signature::<Bls12_381>::public_sign(&messages, &sk, &h);
    let is_valid = public_signature.public_verify(&messages, &pk);
    assert!(is_valid, "Public signature verification failed");
}

#[test]
fn test_commit_and_prove_knowledge() {
    // setup keys and signature first
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    // let (sk: SecretKey<Bls12_381>, pk: PublicKey<Bls12_381>) = keygen(&mut rng, message_count);
    let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, message_count);
    let h = G1Affine::rand(&mut rng);

    // Create messages
    let messages: Vec<Fr> = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // create commitment for blind signature C = g^t sum Yimi
    let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let C = G1Projective::msm_unchecked(&pk.y_g1, &messages) + pk.g1.mul(t);

    // create fake challenge
    let challenge = Fr::rand(&mut rng);

    // gather bases for proving g1, Y1, Y2, ..., Yi
    let mut bases = vec![pk.g1];
    bases.extend(pk.y_g1.iter().cloned());

    // generate commitment for proving
    let com_prime = SchnorrProtocol::commit(&bases, &mut rng);

    // gather exponents to prove t, m1, m2, ..., mi
    let mut exponents = vec![t];
    exponents.extend(messages.iter().cloned());

    assert!(com_prime.random_blindings.len() == bases.len() && bases.len() == exponents.len());

    let response = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);
    let is_valid =
        SchnorrProtocol::verify(&bases, &C.into_affine(), &com_prime, &response, &challenge);

    assert!(is_valid, "Schnorr proof verification failed");
}

#[test]
fn test_commit_and_prove_knowledge_and_SoK() {
    // setup keys and signature first
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    // let (sk: SecretKey<Bls12_381>, pk: PublicKey<Bls12_381>) = keygen(&mut rng, message_count);
    let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, message_count);
    let h = G1Affine::rand(&mut rng);

    // Create messages
    let messages: Vec<Fr> = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // create commitment for blind signature C = g^t sum Yimi
    let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let C = G1Projective::msm_unchecked(&pk.y_g1, &messages) + pk.g1.mul(t);

    // create fake challenge
    let challenge = Fr::rand(&mut rng);

    // gather bases for proving g1, Y1, Y2, ..., Yi
    let mut bases = vec![pk.g1];
    bases.extend(pk.y_g1.iter().cloned());

    // generate commitment for proving
    let com_prime = SchnorrProtocol::commit(&bases, &mut rng);

    // gather exponents to prove t, m1, m2, ..., mi
    let mut exponents = vec![t];
    exponents.extend(messages.iter().cloned());

    assert!(com_prime.random_blindings.len() == bases.len() && bases.len() == exponents.len());

    let response = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);
    let is_valid =
        SchnorrProtocol::verify(&bases, &C.into_affine(), &com_prime, &response, &challenge);

    assert!(is_valid, "Schnorr proof verification failed");

    // if signer is convinced, she signs
    let blind_signature = Signature::<Bls12_381>::blind_sign(&pk, &sk, &C.into_affine(), &mut rng);
    let unblinded_signature = blind_signature.unblind(&t);

    // does this verify?
    let is_valid = unblinded_signature.public_verify(&messages, &pk);
    assert!(is_valid, "Public signature verification failed");

    // Prover selects r, t and computes sigma_prime = (sigma1^r, (sigma2 + sigma1^t)^r)
    let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let tt = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let sigma_prime = unblinded_signature.rerandomize_for_pok(&r, &tt);
    let sigma_prime_1 = sigma_prime.sigma1;
    let sigma_prime_2 = sigma_prime.sigma2;

    // Try Pairing
    // vec g1 = sigma1_prime, sigma1_prime, sigma1_prime, sigma2_prime (is inverse)
    // vec g2 = x_g2, yjmj, g2, g2

    let yimi_points_projective: Vec<G2Projective> = pk
        .y_g2
        .iter()
        .zip(&messages)
        .map(|(y, m)| y.mul(m))
        .collect();

    let yimi_points_affine = G2Projective::normalize_batch(&yimi_points_projective);

    let yimi_g2s: Vec<G2Prepared<Bls12_381Config>> = yimi_points_affine
        .into_iter()
        .map(G2Prepared::from)
        .collect();

    let sigma1_prime_vec = vec![sigma_prime.sigma1; message_count];

    let a: G1Prepared<Bls12_381Config> = G1Prepared::from(sigma_prime_1);
    let b: G2Prepared<Bls12_381Config> = G2Prepared::from(pk.x_g2);

    let multi_c = sigma1_prime_vec;
    let multi_d = yimi_g2s;

    let e: G1Prepared<Bls12_381Config> = G1Prepared::from(sigma_prime_1);
    let f: G2Prepared<Bls12_381Config> = G2Prepared::from(pk.g2.mul(tt));

    let g: G1Prepared<Bls12_381Config> = G1Prepared::from(sigma_prime_2.neg());
    let h: G2Prepared<Bls12_381Config> = G2Prepared::from(pk.g2);


    let pairing_miller_loop_1 = Bls12_381::multi_miller_loop([a, e, g], [b, f, h]);
    let result_1 = Bls12_381::final_exponentiation(pairing_miller_loop_1).unwrap();
    let is_valid_1 = PairingOutput::is_zero(&result_1);
    assert!(is_valid_1, "Final Pairing verification failed");
}
