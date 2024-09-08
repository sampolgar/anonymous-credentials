// https://github.com/docknetwork/crypto/blob/main/syra/src/vrf.rs#L84
// asymettric vrf

use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
// {AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    test_rng, One, UniformRand, Zero,
};
// use itertools::Itertools;
use core::marker::PhantomData;
use rayon::prelude::*;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

// secret key sk s
// public key pk
// secret message x

// prove(sk, x) -> Fsk(x), π
// verify(x, y, π, pk)

#[derive(Clone, Debug)]
pub struct Secrets<E: Pairing> {
    pub x: E::ScalarField,
    pub s: E::ScalarField,
    pub y: E::G1Affine,
}

pub struct PublicKey<E: Pairing> {
    pub pk: E::G1Affine,
    pub g: E::G1Affine, // This is our random generator point
}

pub struct VrfProof<E: Pairing> {
    pub y: E::G1Affine,
    pub t_commitment: SchnorrCommitment<E::G1Affine>,
    pub t_responses: SchnorrResponses<E::G1Affine>,
    pub challenge: E::ScalarField,
}

pub struct VRF<E: Pairing> {
    _phantom: PhantomData<E>,
}

impl<E: Pairing> VRF<E> {
    pub fn new() -> Self {
        VRF {
            _phantom: PhantomData,
        }
    }
    pub fn keygen<R: Rng>(rng: &mut R) -> (E::ScalarField, PublicKey<E>) {
        let sk = E::ScalarField::rand(rng);
        let g = E::G1::rand(rng).into_affine();
        let pk = g.mul(sk).into_affine();
        (sk, PublicKey { pk, g })
    }

    pub fn evaluate(sk: &E::ScalarField, x: &E::ScalarField, g: &E::G1Affine) -> E::G1Affine {
        let inv_exponent = (*sk + *x).inverse().expect("sk + x should not be zero");
        g.mul(inv_exponent).into_affine()
    }

    // prover knows sk, x, y such that g^1/sk+x
    // let z = sk + x. We prove knowledge of z = sk + x not 1/sk+x
    // public_statement = y (= g^1/sk+x)
    // t_commitment = g^1/r, r \in Zp
    // challenge = c, \in Zp
    // t_response = r + c * z
    // verify by t * y^c
    pub fn prove<R: Rng>(
        sk: &E::ScalarField,
        x: &E::ScalarField,
        g: &E::G1Affine,
        rng: &mut R,
    ) -> VrfProof<E> {
        let z = *sk + *x;
        let y = g
            .mul(z.inverse().expect("sk + x should not be zero"))
            .into_affine();

        // Commit
        let t_commitment = SchnorrProtocol::commit(&[*g], rng);
        let challenge = E::ScalarField::rand(rng);
        // Prove
        let t_responses = SchnorrProtocol::prove(&t_commitment, &[z], &challenge);

        VrfProof {
            y,
            t_commitment,
            t_responses,
            challenge,
        }
    }

    pub fn verify(proof: &VrfProof<E>, x: &E::ScalarField, pk: &PublicKey<E>) -> bool {
        // Verify the Schnorr proof
        let is_proof_valid = SchnorrProtocol::verify(
            &[pk.g],
            &proof.y,
            &proof.t_commitment,
            &proof.t_responses,
            &proof.challenge,
        );

        // Verify that e(g, y) = e(pk * g^x, g2)
        let g1 = E::G1Affine::generator();
        let g2 = E::G2Affine::generator();
        let lhs = E::pairing(proof.y, g2);
        let rhs = E::pairing(pk.pk.mul(*x).add(g1).into_affine(), g2);

        is_proof_valid && (lhs == rhs)
    }
}

use ark_bls12_381::{Bls12_381, Fr, G1Affine};

#[test]
fn test_vrf() {
    let mut rng = test_rng();

    // Key generation
    let (sk, pk) = VRF::<Bls12_381>::keygen(&mut rng);

    // Create a random input
    let x = Fr::rand(&mut rng);

    // Evaluate VRF
    let y = VRF::<Bls12_381>::evaluate(&sk, &x, &pk.g);

    // Generate proof
    let proof = VRF::<Bls12_381>::prove(&sk, &x, &pk.g, &mut rng);

    // Verify proof
    let is_valid = VRF::<Bls12_381>::verify(&proof, &x, &pk);

    assert!(is_valid, "VRF proof verification failed");

    // Verify that the y in the proof matches the evaluated y
    assert_eq!(y, proof.y, "Evaluated y does not match proof y");

    // Try to verify with incorrect x
    let incorrect_x = Fr::rand(&mut rng);
    let is_invalid = VRF::<Bls12_381>::verify(&proof, &incorrect_x, &pk);

    assert!(!is_invalid, "VRF verification should fail with incorrect x");
}
