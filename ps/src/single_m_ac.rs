use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_std::test_rng;
use ark_std::UniformRand;
use std::ops::{Add, Mul};

type G1A = G1Affine;
type G2A = G2Affine;
type g1 = G1A::generator();
type g2 = G2A::generator();

#[derive(Clone)]
pub struct SecretKey {
    x1: G1A,
}

#[derive(Clone)]
pub struct PublicKey {
    y1: G1A,
    x2: G2A,
    y2: G2A,
}

#[derive(Clone)]
pub struct Signature {
    sigma_1: G1A,
    sigma_2: G1A,
}

pub struct PedersenCommitment {
    pub c: G1Affine,
    t: Fr, // Keep this private
    m: Fr, // Keep this private
}

pub struct ProofOfKnowledge {
    pub c_prime: G1A,
    pub e: Fr,
    pub z1: Fr,
    pub z2: Fr,
}

// C = g^mh^r
pub fn pedersen_commitment_1(g: &G1A, m: &Fr, h: &G1A, r: &Fr) -> G1A {
    (g.mul(m) + h.mul(r)).into_affine()
}

// // (g, h)
// pub fn generate_commitment_key<R: test_rng()>(rng: &mut R) -> (G1A, G1A) {
//     let g = g1;
//     let y = G1A::rand(&mut rng);
//     (g, y)
// }

pub fn generate_keys<R: Rng>(rng: &mut R) -> (SecretKey, PublicKey) {
    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);

    SecretKey {
        x1: g1.mul(x).into_affine(),
    };

    PublicKey {
        y1: g1.mul(y).into_affine(),
        x2: g2.mul(x).into_affine(),
        y2: g2.mul(y).into_affine(),
    };

    (SecretKey, PublicKey)
}

// pub fn generate_commitment_PoK
// generate NIZK proofs of knowledge for signature request

// C \gets g^mh^r, C \to Issuer
pub fn request_signature<R: Rng>(rng: &mut R, pk: &PublicKey) {
    let m = Fr::rand(&mut rng);
    let t = Fr::rand(&mut rng);
    let commitment = pedersen_commitment_1(g1, t, pk.y1, m);
    // pok commitment
}

// pub fn verify_commitment_proofs(){}

// pub fn sign(proofs, commitment){
// verify proofs
// return signed commitment
// }

// pub fn unblind

// pub fn prove knowledge of signature
// pub fn verify signature proofs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen() {}

    #[test]
    fn test_signature() {
        // gen keys
        // has message
        // gens commitment
        // gives to signer with PoK
        // signer verifiers PoK
        // signer signs
    }
}
