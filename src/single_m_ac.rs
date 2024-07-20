// use super::hash::HashUtil;
// use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
// use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
// use ark_std::{test_rng, UniformRand};
// use lazy_static::lazy_static;
// use std::ops::{Add, Mul};

// type G1A = G1Affine;
// type G2A = G2Affine;

// lazy_static! {
//     static ref G1: G1A = G1A::generator();
//     static ref G2: G2A = G2A::generator();
// }

// #[derive(Clone)]
// pub struct SecretKey {
//     x1: G1A,
// }

// #[derive(Clone)]
// pub struct PublicKey {
//     y1: G1A,
//     x2: G2A,
//     y2: G2A,
// }

// #[derive(Clone)]
// pub struct Signature {
//     sigma_1: G1A,
//     sigma_2: G1A,
// }

// pub struct PedersenCommitment {
//     pub c: G1Affine,
//     t: Fr,
//     m: Fr,
// }

// pub struct ProofOfKnowledge {
//     pub c_prime: G1A,
//     pub e: Fr,
//     pub z1: Fr,
//     pub z2: Fr,
// }

// // C = g^mh^r
// pub fn pedersen_commitment_1(g: &G1A, m: &Fr, h: &G1A, r: &Fr) -> G1A {
//     (g.mul(m) + h.mul(r)).into_affine()
// }

// pub fn generate_keys<R: UniformRand>(rng: &mut R) -> (SecretKey, PublicKey) {
//     let x = Fr::rand(&mut test_rng());
//     let y = Fr::rand(&mut test_rng());

//     let sk = SecretKey {
//         x1: G1.mul(x).into_affine(),
//     };

//     let pk = PublicKey {
//         y1: G1.mul(y).into_affine(),
//         x2: G2.mul(x).into_affine(),
//         y2: G2.mul(y).into_affine(),
//     };

//     (sk, pk)
// }

// // fn compute_challenge()

// // pub fn generate_commitment_PoK
// // generate NIZK proofs of knowledge for signature request

// // c \gets g^tY^m, C \to Issuer
// pub fn request_signature<R: UniformRand>(rng: &mut R, pk: &PublicKey) {
//     let m = Fr::rand(&mut test_rng());
//     let t = Fr::rand(&mut test_rng());
//     let c = pedersen_commitment_1(&G1, &t, &pk.y1, &m);

//     // generate c_prime components. g^t_prime, Y^m_prime
//     let m_prime = Fr::rand(&mut test_rng());
//     let t_prime = Fr::rand(&mut test_rng());
//     let c_prime = pedersen_commitment_1(&G1, &t_prime, &pk.y1, &m_prime);

//     // generate challenge

//     let pok = ProofOfKnowledge {
//         c_prime: c_prime,
//         e: Fr::rand(&mut &mut test_rng()),
//         z1: Fr::rand(&mut &mut test_rng()),
//         z2: Fr::rand(&mut &mut test_rng()),
//     };
//     // pok commitment
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_keygen() {}

//     #[test]
//     fn test_signature() {
//         // gen keys
//         // has message
//         // gens commitment
//         // gives to signer with PoK
//         // signer verifiers PoK
//         // signer signs
//     }

//     #[test]
//     fn test_hasher() {
//         let message = b"Hello";
//         let field_element_hash = HashUtil::hash_to_curve(message);
//         let curve_point_hash = HashUtil::hash_to_curve(message);

//         println!("Field element: {:?}", field_element_hash);
//         println!("Curve point: {:?}", curve_point_hash);

//         let multiple_fields = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
//         let hashed_fields = HashUtil::hash_fields(&multiple_fields);
//         println!("Hashed fields: {:?}", hashed_fields);
//     }
// }
