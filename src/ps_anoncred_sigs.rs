use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;
use crate::pairing::PairingCheck;
use crate::pairing_util::PairingTuple;
use crate::pairs::PairingUtils;
use ark_bls12_381::{Bls12_381, G2Projective};

use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::uint;
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
        let sigma1_temp = self.sigma1.clone();
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: (self.sigma2.into_group() + sigma1_temp.mul(*t))
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

        let multi_pairing = E::multi_pairing([a, c], [b, d]);
        assert!(multi_pairing.0.is_one());
        true

        // let pairing_miller_loop = E::multi_miller_loop([a, c], [b, d]);
        // let result = E::final_exponentiation(pairing_miller_loop).unwrap();
        // PairingOutput::is_zero(&result)
    }
}

// keygen(&message_count) handover the address of this
// keygen(message_count) copy the message_count to whatever we're calling

// fn(&message_count: &usize)  this doesn't make sense, handover the reference to the non-existing variable

// fn(message_count: &usize) // &usize is a reference to the data type
// keygen(&message_count)   //
// let y = *message_count  needs to use *message_count. This is saying, handover a reference to the data type

// fn(message_count: usize)
// keygen(message_count) copy message_count when using keygen
// let y = message_count no reference needed because we have the value itself

// simple understanding
// keygen(&message_count); calls a function, passes a reference to the message_count
// keygen(message_count); calls a function, passes a copy of the message_count

// let y = message_count assigns message_count to y. message_count needs to be the value and not a reference
// let y = *message_count assigns y the value of the reference message_count

// fn(message_count: usize) takes a copy of a data type usize and names it message_count
// fn(message_count: &usize) takes a reference of a usize and names it message_count

//
//
//
fn keygen<E: Pairing, R: Rng>(rng: &mut R, message_count: &usize) -> (SecretKey<E>, PublicKey<E>) {
    // setup random g points for public key
    print!("{}", message_count);
    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    // generate x and y_i for each message
    let x = E::ScalarField::rand(rng);
    let yi = (0..*message_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = g1.mul(x).into_affine();
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

fn testkeygen<E: Pairing, R: Rng>(
    rng: &mut R,
    message_count: &usize,
) -> (SecretKey<E>, PublicKey<E>) {
    // setup random g points for public key
    print!("{}", message_count);

    let g1 = E::G1Affine::generator();
    let g2 = E::G2Affine::generator();

    // testing
    let x = E::ScalarField::one();
    let y1 = <E as Pairing>::ScalarField::one() + <E as Pairing>::ScalarField::one();
    let y2 = y1 + <E as Pairing>::ScalarField::one();
    let y3 = y2 + <E as Pairing>::ScalarField::one();
    let y4 = y3 + <E as Pairing>::ScalarField::one();

    let yi: Vec<<E as Pairing>::ScalarField> = vec![y1, y2, y3, y4];

    let x_g1 = g1.mul(x).into_affine();
    let y1_g1 = g1 * y1;
    let y2_g1 = g1 * y2;
    let y3_g1 = g1 * y3;
    let y4_g1 = g1 * y4;

    let y_g1 = E::G1::normalize_batch(&[y1_g1, y2_g1, y3_g1, y4_g1]);

    let x_g2 = g2.mul(x).into_affine();
    let y1_g2 = g2 * y1;
    let y2_g2 = g2 * y2;
    let y3_g2 = g2 * y3;
    let y4_g2 = g2 * y4;
    let y_g2 = E::G2::normalize_batch(&[y1_g2, y2_g2, y3_g2, y4_g2]);

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
use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
use ark_std::test_rng;

#[test]
fn test_pairs() {
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, &message_count);

    let g1_points = pk.y_g1.clone();
    let scalars = sk.yi.clone();

    let scaled_g1_points = PairingUtils::<Bls12_381>::scale_g1(&g1_points, &scalars);

    let prepared_g1 = PairingUtils::<Bls12_381>::prepare_g1(&scaled_g1_points);
    let prepared_g2 = PairingUtils::<Bls12_381>::prepare_g2(&pk.y_g2);

    let miller_loop_result = PairingUtils::<Bls12_381>::multi_miller_loop(prepared_g1, prepared_g2);

    let pairing_result = PairingUtils::<Bls12_381>::final_exponentiation(miller_loop_result);

    assert!(pairing_result.is_some());
}

#[test]
fn test_sign_and_verify() {
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, &message_count);

    // Create messages
    let messages: Vec<Fr> = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let h = G1Affine::rand(&mut rng);
    let public_signature = Signature::<Bls12_381>::public_sign(&messages, &sk, &h);
    let is_valid = public_signature.public_verify(&messages, &pk);
    assert!(is_valid, "Public signature verification failed");
}

// #[test]
// fn test_commit_and_prove_knowledge() {
//     // setup keys and signature first
//     let message_count = 4;
//     let mut rng = ark_std::test_rng();
//     // let (sk: SecretKey<Bls12_381>, pk: PublicKey<Bls12_381>) = keygen(&mut rng, message_count);
//     let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, &message_count);
//     let h = G1Affine::rand(&mut rng);

//     // Create messages
//     let messages: Vec<Fr> = (0..message_count)
//         .map(|_| Fr::rand(&mut rng))
//         .collect::<Vec<_>>();

//     // create commitment for blind signature C = g^t sum Yimi
//     let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
// let C = G1Projective::msm_unchecked(&pk.y_g1, &messages) + pk.g1.mul(t);

//     // create fake challenge
//     let challenge = Fr::rand(&mut rng);

//     // gather bases for proving g1, Y1, Y2, ..., Yi
//     let mut bases = vec![pk.g1];
//     bases.extend(pk.y_g1.iter().cloned());

//     // generate commitment for proving
//     let com_prime = SchnorrProtocol::commit(&bases, &mut rng);

//     // gather exponents to prove t, m1, m2, ..., mi
//     let mut exponents = vec![t];
//     exponents.extend(messages.iter().cloned());

//     assert!(com_prime.random_blindings.len() == bases.len() && bases.len() == exponents.len());

//     let response = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);
//     let is_valid =
//         SchnorrProtocol::verify(&bases, &C.into_affine(), &com_prime, &response, &challenge);

//     assert!(is_valid, "Schnorr proof verification failed");
// }

#[test]
fn test_commit_and_prove_knowledge_and_SoK() {
    // setup keys and signature first
    let message_count = 4;
    let mut rng = ark_std::test_rng();
    let (sk, pk) = keygen::<Bls12_381, _>(&mut rng, &message_count);
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

    
    // Signature of Knowledge
    // 
    // Prover selects r, t and computes sigma_prime = (sigma1^r, (sigma2 + sigma1^t)^r)
    let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let tt = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let sigma_prime = unblinded_signature.rerandomize_for_pok(&r, &tt);
    let sigma_prime_1 = sigma_prime.sigma1;
    let sigma_prime_2 = sigma_prime.sigma2;

    let a = sigma_prime_1.clone();
    print!("a, {}", a);
    let b = pk.x_g2;
    print!("b, {}", a);
    let ab = Bls12_381::pairing(a, b);

    let c = sigma_prime_1.clone();
    let dish = G2Projective::msm_unchecked(&pk.y_g2, &messages);
    let cdish = Bls12_381::pairing(c, dish);

    let c0 = sigma_prime_1.clone();
    let c1 = sigma_prime_1.clone();
    let c2 = sigma_prime_1.clone();
    let c3 = sigma_prime_1.clone();

    let d0 = pk.y_g2[0].mul(messages[0]);
    let d1 = pk.y_g2[1].mul(messages[1]);
    let d2 = pk.y_g2[2].mul(messages[2]);
    let d3 = pk.y_g2[3].mul(messages[3]);

    let c0d0 = Bls12_381::pairing(c0, d0);
    let c1d1 = Bls12_381::pairing(c1, d1);
    let c2d2 = Bls12_381::pairing(c2, d2);
    let c3d3 = Bls12_381::pairing(c3, d3);

    let vec_of_sigmap =
        PairingUtils::<Bls12_381>::copy_point_to_length(sigma_prime_1.clone(), &message_count);

    assert!(vec_of_sigmap.len() == sk.yi.len());

    let c_vec = PairingUtils::<Bls12_381>::scale_g1(&vec_of_sigmap, &messages);
    // let d_vec2 = PairingUtils::<Bls12_381>::scale_g2(&pk.y_g2.clone(), &sk.yi);
    let d_vec = pk.y_g2.clone();

    let c0d0prime = Bls12_381::pairing(c_vec[0], d_vec[0]);
    let c1d1prime = Bls12_381::pairing(c_vec[1], d_vec[1]);
    let c2d2prime = Bls12_381::pairing(c_vec[2], d_vec[2]);
    let c3d3prime = Bls12_381::pairing(c_vec[3], d_vec[3]);

    // assert!(d0 == d_vec2[0], "g2 points aren't equal!");
    assert!(c0d0 == c0d0prime, "0 isn't equal!!!");
    assert!(c1d1 == c1d1prime, "1 isn't equal!!!");
    assert!(c2d2 == c2d2prime, "2 isn't equal!!!");
    assert!(c3d3 == c3d3prime, "3 isn't equal!!!");

    let e = sigma_prime_1.clone().into_group().mul(tt).into_affine();
    let f = pk.g2;

    let ef = Bls12_381::pairing(e, f);

    let g_right = sigma_prime_2.into_group().neg().into_affine();
    let g = sigma_prime_2.clone();
    let h_right = pk.g2;

    let gh = Bls12_381::pairing(g_right, h_right);
    let cd = c0d0 + c1d1 + c2d2 + c3d3;
    println!("cd point is: {}", cd);
    let sum = ab + c0d0 + c1d1 + c2d2 + c3d3 + ef + gh;
    // let sum = ab + cdish + ef + gh;
    assert!(sum.is_zero());

    let g1_pairing_points = PairingUtils::<Bls12_381>::combine_g1_points(&c_vec, &[a, e, g_right]);
    let g2_pairing_points = PairingUtils::<Bls12_381>::combine_g2_points(&d_vec, &[b, f, h_right]);

    assert!(g1_pairing_points.len() == message_count + 3);
    let prepared_g1_points = PairingUtils::<Bls12_381>::prepare_g1(&g1_pairing_points);
    let prepared_g2_points = PairingUtils::<Bls12_381>::prepare_g2(&g2_pairing_points);

    let multi_pairing = Bls12_381::multi_pairing(prepared_g1_points, prepared_g2_points);
    print!("multi pairing: {}", multi_pairing.0);
    assert!(multi_pairing.0.is_one());

    let gt_identity = <Bls12_381 as Pairing>::TargetField::one();
    println!("GT Identity: {}", gt_identity);
}

// // add multi-message struct to deal with that easier
// //
