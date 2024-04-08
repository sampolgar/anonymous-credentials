// use ark_bls12_381::{
//     Bls12_381, Fr as ScalarField, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2,
// };
// use ark_ff::{BigInteger, Field, PrimeField};

// use ark_ec::pairing::{Pairing, PairingOutput};
// use ark_ec::{AffineRepr, Group, ScalarMul, VariableBaseMSM};

// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
// use ark_std::UniformRand;

// // key gen
// // q = field modulus
// // G1 G2 generator_g1 generator_g2, e,
// // scalar x, y
// // Group elem X, Y
// pub fn key_gen() {
//     // return
//     let mut rng = ark_std::rand::thread_rng();
//     let x = Fq::rand(&mut rng);
//     let y = Fq::rand(&mut rng);
//     let g1 = G1Projective::rand(&mut rng);
//     let g2 = G2Affine::rand(&mut rng);
//     let X1 = g1.mul(&x);
//     let Y1 = y.mul(&g2);
// }

// // sign
// // input m, sk, pk
// // chose random a
// // sigma (a,b,c) = (a*G1 + b*G2, )

// // verify
// // e(a,Y) = e(g,b)
// // e(X,a) . e(X,b^m) = e(g,c)

// //pos2 is G2
// // X = G1, Y = G2
// // a = G1, b = G2

// // a = G2, b = G2, c = G2
