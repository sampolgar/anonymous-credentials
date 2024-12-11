// use crate::{
//     commitment::Commitment,
//     ps_helpers::{g1_commit, g2_commit, g1_commit_schnorr, g2_commit_schnorr},
//     publicparams::PublicParams,
// };
// use ark_ec::{pairing::Pairing, ScalarMul};
// use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
// use ark_ff::{PrimeField, UniformRand};
// use ark_std::{cfg_iter, ops::{Add, Mul, Neg}};
// use ark_std::rand::Rng;
// use digest::Digest;

// pub struct ProofCommitmentOpeningG1<E: Pairing> {
//     pub pp: PublicParams<E>,
//     pub commitment: E::G1Affine,
//     pub messages: Vec<E::ScalarField>,
//     pub r: E::ScalarField,
//     pub blinding_commitment: E::G1Affine,
//     pub blinding_factors: Vec<E::ScalarField>,
//     pub responses: Vec<E::ScalarField>,
// }

// pub struct SigmaCommitmentG1<E: Pairing>{
//     pub blindings: Vec<E::ScalarField>,
//     pub blinding_commitment: E::G1Affine,
// }

// pub fn prove_commitment_opening_g1<E: Pairing, R: Rng>(
//     pp: &PublicParams<E>,
//     commitment: &Commitment<E>,
//     rng: &mut R,
// ) -> ProofCommitmentOpeningG1 {
//     let blinding_factors: Vec<E::ScalarField> =
//         (0..pp.n+1).map(|_| E::ScalarField::rand(&mut rng)).collect();

//     let bases: Vec<E::G1Affine> = pp.get_g1_bases();
//     let blinding_commitment = g1_commit_schnorr(&pp, &blinding_factors);

//     // pub fn new(bases: &[G], blindings: Vec<G::ScalarField>) -> Self {
//     //     let t = G::Group::msm_unchecked(bases, &blindings).into_affine();
//     //     Self { blindings, t }
//     // }

//     // create challenge
//     let challenge = E::ScalarField::rand(&mut rng);

//     let responses = cfg_iter!()

//     // let responses = cfg_iter!(self.blindings)
//     //         .zip(cfg_iter!(witnesses))
//     //         .map(|(b, w)| *b + (*w * *challenge))
//     //         .collect::<Vec<_>>();
//     //     Ok(SchnorrResponse(responses))
//     // create responses
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::commitment::Commitment;
//     use crate::publicparams::PublicParams;
//     use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
//     use ark_std::test_rng;

//     #[test]
//     fn test_sigma() {
//         // prepare for proof
//         let mut rng = test_rng();
//         let pp = PublicParams::<Bls12_381>::new(&4, &mut rng);
//         let messages: Vec<Fr> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
//         let r = Fr::rand(&mut rng);
//         let commitment = Commitment::<Bls12_381>::new(&pp, &messages, &r);

//         let blinding_factors: Vec<Fr> = (0..pp.n + 1).map(|_| Fr::rand(&mut rng)).collect();
//     }
// }
