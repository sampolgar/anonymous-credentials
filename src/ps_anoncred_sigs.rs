use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;
use super::schnorr::SchnorrProtocol;
use crate::pairing::PairingCheck;
use crate::pairing_util::PairingTuple;
use ark_bls12_381::Bls12_381;

use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
struct PublicParams<E: Pairing> {
    g1: E::G1Affine,
    g2: E::G2Affine,
}

struct SecretKey<F: PrimeField, E: Pairing> {
    x: F,
    yi: Vec<F>,
    x_g1: E::G1Affine, //X_1 secret key
}

struct PublicKey<E: Pairing> {
    ck_g1: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    ck_g2: Vec<E::G2Affine>, //[X_2, Y_1, Y_2, ..., Y_n]
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
        E::G1: CurveGroup<ScalarField = E::ScalarField>, // Add this trait bound
    {
        let mut witnesses: Vec<E::ScalarField> = messages.to_vec();
        witnesses.insert(0, *t);
        let commitment: E::G1Affine = E::G1::msm_unchecked(&pk.ck_g1, &witnesses).into_affine();
        commitment
    }

    pub fn blind_sign<R: Rng>(
        params: &PublicParams<E>,
        sk: &SecretKey<E::ScalarField, E>,
        commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        // sigma_prime \gets (g^u, (g^x + C)^u)
        let u = E::ScalarField::rand(rng);
        let sigma1 = params.g1.mul(u).into_affine();
        let sigma2 = (params.g1.mul(sk.x) + commitment).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn unblind(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1,
            sigma2: (self.sigma2.into_group() - self.sigma1.mul(*t)).into_affine(),
        }
    }

    pub fn rerandomize<R: Rng>(&self, params: &PublicParams<E>, rng: &mut R) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1_prime = params.g1.mul(u).into_affine();
        let sigma2_prime = (self.sigma2.into_group() + params.g1.mul(u)).into_affine();
        Self {
            sigma1: sigma1_prime,
            sigma2: sigma2_prime,
        }
    }

    pub fn public_verify(
        &self,
        params: &PublicParams<E>,
        pk: &PublicKey<E>,
        commitment: &E::G1Affine,
    ) -> bool {
        let mut rng = test_rng();
        let mr = Mutex::new(rng);
        let commitment_inv = commitment.into_group().neg().into_affine();
        let g1_points = [self.sigma1, self.sigma2, commitment_inv];
        let g2_points = [pk.ck_g2[0], params.g2, params.g2];

        let g1_points2 = [
            self.sigma1,
            *commitment,
            self.sigma2.into_group().neg().into_affine(),
        ];
        let g2_points2 = [pk.ck_g2[0], params.g2, params.g2];

        let pairing_tuples: Vec<(&E::G1Affine, &E::G2Affine)> =
            g1_points2.iter().zip(g2_points2.iter()).collect();
        let expected_result = E::TargetField::one();
        let pairing_check = PairingCheck::<E>::rand(&mr, &pairing_tuples, &expected_result);

        pairing_check.verify()
    }
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
        g1: E::G1::rand(rng).into_affine(),
        g2: E::G2::rand(rng).into_affine(),
    }
}

fn keygen<E: Pairing, R: Rng>(
    params: &PublicParams<E>,
    rng: &mut R,
    message_count: usize,
) -> (SecretKey<E::ScalarField, E>, PublicKey<E>) {
    let x = E::ScalarField::rand(rng);
    let yi = (0..message_count)
        .map(|_| E::ScalarField::rand(rng))
        .collect::<Vec<_>>();

    let x_g1 = params.g1.mul(x).into_affine();
    let ck_g1 = yi
        .iter()
        .map(|yi| params.g1.mul(yi).into_affine())
        .collect::<Vec<_>>();

    let x_g2 = params.g2.mul(x).into_affine();
    let mut ck_g2 = yi
        .iter()
        .map(|yi| params.g2.mul(yi).into_affine())
        .collect::<Vec<_>>();
    ck_g2.insert(0, x_g2.clone());

    (SecretKey { x, yi, x_g1 }, PublicKey { ck_g1, ck_g2 })
}

// fn generate_signature_of_knowledge<E: Pairing, R: Rng>(
//     params: &PublicParams<E>,
//     pk: &PublicKey<E>,
//     signature: &Signature<E>,
//     secret_witnesses: &[E::ScalarField],
//     challenge: &E::ScalarField,
//     rng: &mut R,
// ) -> SignatureProof<E> {
//     // rerandomize signature

//     // e(sigma_1', x_g2) * ∑ e(sigma_1', y_i) * e(sigma1', g2)^t = e(sigma_2', g2)
//     // ∑ e(sigma_1', y_i)^m_i * e(sigma1', g2)^t  = e(sigma_2', g2) - e(sigma_1', x_g2)

//     // create public statement e(sigma_2', g2) - e(sigma_1', x_g2) in PairingCheck

//     // commit to m_i and t as G1 elements.
//     // e(sigma_1', g2)^beta => sigma1'*beta
//     // e(sigma1', y_i)^m_i => sigma1' * Y_i
//     // commit to m_i and t as GT elements. similar to schnorr prior protocol, the bases are
//     // 1 e(sigma_1', g2) for beta
//     // 2i e(sigma_1', y_i) for each alpha_i
//     // commitment_prime is T = one GT point composed of 1, 2i = e(sigma_1', g2)^beta * e(sigma_1', y_i)^mi

//     // responses
//     // z_t = beta + challenge * t
//     // z_i = alpha_i + challenge * m_i

//     // proofs sent are z_t, z_i, sigma', com_prime
//     // verifier does base_1^z_t * base_i^z_i = sigma'^challenge * T
// }

#[cfg(test)]
use super::*;
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_std::test_rng;

#[test]
fn test_setup3() {
    let mut rng = test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);

    assert!(!params.g1.is_zero());
    assert!(!params.g2.is_zero());

    let x = Fr::rand(&mut rng);
    let n = 5; // Choose an appropriate size for yi vector
    let yi: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    let x_g1 = params.g1.mul(x).into_affine();

    // Create secret key
    let sk = SecretKey::<Fr, Bls12_381> {
        x,
        yi: yi.clone(),
        x_g1,
    };

    // Create public key
    let ck_g1: Vec<_> = yi.iter().map(|y| params.g1.mul(y).into_affine()).collect();
    let mut ck_g2 = vec![params.g2.mul(x).into_affine()];
    ck_g2.extend(yi.iter().map(|y| params.g2.mul(y).into_affine()));
    let pk = PublicKey::<Bls12_381> { ck_g1, ck_g2 };

    // Perform assertions to verify the setup
    assert_eq!(sk.yi.len(), n);
    assert_eq!(pk.ck_g1.len(), n);
    assert_eq!(pk.ck_g2.len(), n + 1);
    assert_eq!(sk.x_g1, params.g1.mul(sk.x).into_affine());

    // You can add more assertions here to verify the correctness of the setup
}

#[test]
fn test_sign_and_verify() {
    let message_count = 2;
    let mut rng = ark_std::test_rng();
    let params: PublicParams<Bls12_381> = setup(&mut rng);
    let (sk, pk) = keygen(&params, &mut rng, message_count);

    // Create messages
    let messages: Vec<Fr> = (0..message_count)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // Prepare Blind Sign, C \gets g^t \prod_{i=1}^{n} Y_i^{m_i}.
    let t = Fr::rand(&mut rng);
    let commitment = Signature::<Bls12_381>::prepare_blind_sign(&messages, &t, &pk);

    // generate proof of opening

    // get blind signature
    let signature = Signature::blind_sign(&params, &sk, &commitment, &mut rng);

    let unblind_signature = signature.unblind(&t);

    // Verify
    assert!(unblind_signature.public_verify(&params, &pk, &commitment));
}

// #[test]
// fn test_commit_and_prove_knowledge() {
//     let mut rng = test_rng();
//     let params: PublicParams<Bls12_381> = setup(&mut rng);
//     let num_messages = 2;
//     let (sk, pk) = keygen(&params, &mut rng, num_messages);

//     // create messages
//     let t = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
//     let mut messages: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..num_messages)
//         .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
//         .collect();
//     messages.insert(0, t);

//     let mut bases = pk.ck_g1.clone();
//     bases.insert(0, params.g1);

//     // generate commitment to messages
//     let com = G1Projective::msm_unchecked(&bases, &messages).into_affine();

//     let challenge = Fr::rand(&mut rng); // In practice, this should be derived from a hash

//     // generate commitment for proving
//     let com_prime = SchnorrProtocol::commit(&bases, &mut rng);
//     let response = SchnorrProtocol::prove(&com_prime, &messages, &challenge);
//     let is_valid = SchnorrProtocol::verify(&bases, &com, &com_prime, &response, &challenge);

//     assert!(is_valid, "Schnorr proof verification failed");
// }
