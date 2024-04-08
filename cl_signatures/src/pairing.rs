// // use ark_ec::{pairing::Pairing, AffineRepr};
// // use ark_ff::Field;
// // use ark_std::UniformRand;

// // use ark_test_curves::bls12_381::Fr as ScalarField;
// // use ark_test_curves::bls12_381::{Bls12_381, Fq12, G1Projective as G1, G2Projective as G2};

// // pub fn test_pairing() {
// //     let mut rng = ark_std::test_rng();
// //     let s = ScalarField::rand(&mut rng);
// //     let a = G1::rand(&mut rng);
// //     let b = G2::rand(&mut rng);

// //     let e1 = Bls12_381::pairing(a, b);
// //     let ml_result = Bls12_381::pairing::miller_loop(a, b);
// //     let e2 = Bls12_381::final_exponentiation(ml_rest).unwrap();
// //     assert_eq!(e1, e2);
// // }

// // use ark_bls12_381::{Fr as ScalarField, G1Affine as GAffine, G1Projective as G};
// // use ark_ec::{AffineCurve, ProjectiveCurve};
// // use ark_ff::{Field, PrimeField};
// // use ark_std::{UniformRand, Zero};

// // use ark_ec::Group;
// // use ark_ff::{Field, PrimeField};
// // use ark_std::{ops::Mul, UniformRand, Zero};
// // use bls12_381::{G1Projective as G, Scalar as F};

// use ark_bls12_381::Fq2 as F;
// use ark_ff::{Field, PrimeField};
// use ark_std::{One, Zero, UniformRand};

// pub fn key_gen() {
//     let mut rng = ark_std::rand::thread_rng();
//     let x = F::rand(&mut rng);
//     let y = F::rand(&mut rng);

//     // let X:
// }


// // use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
// // use ark_ec::pairing::{Pairing, PairingOutput};
// // use ark_ec::{AffineRepr, Group, ScalarMul, VariableBaseMSM};
// // use ark_ff::One;
// // use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};