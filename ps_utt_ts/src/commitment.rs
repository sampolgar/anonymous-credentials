// use crate::proofsystem::{CommitmentProof, CommitmentProofError, CommitmentProofs};
// use crate::publicparams::PublicParams;
// use ark_ec::pairing::Pairing;
// use ark_ec::{CurveGroup, VariableBaseMSM};
// use ark_ff::UniformRand;
// use ark_std::ops::{Add, Mul, Neg};
// use ark_std::rand::Rng;
// use schnorr::schnorr::SchnorrProtocol;

// #[derive(Clone)]
// pub struct Commitment<E: Pairing> {
//     pub pp: PublicParams<E>,
//     pub messages: Vec<E::ScalarField>,
//     pub r: E::ScalarField,
//     pub cmg1: E::G1Affine,
//     pub cmg2: E::G2Affine,
// }

// // takes in pp, messages, r. creates cmg1, cmg2 by 1. exponentiate each pp.ckg1 with mi and pp.g1 with r, msm together
// impl<E: Pairing> Commitment<E> {
//     pub fn new(pp: &PublicParams<E>, messages: &Vec<E::ScalarField>, r: &E::ScalarField) -> Self {
//         let cmg1 = g1_commit::<E>(pp, messages, r);
//         let cmg2 = g2_commit::<E>(pp, messages, r);
//         Commitment {
//             pp: pp.clone(),              // this clones pp for the commitment
//             messages: messages.to_vec(), // this creates its own messages
//             r: *r,
//             cmg1,
//             cmg2,
//         }
//     }

//     pub fn randomize(&self, r_delta: &E::ScalarField) -> Self {
//         let new_r = self.r + r_delta;
//         let cmg1_delta = (self.cmg1 + self.pp.g1.mul(r_delta)).into_affine();
//         let cmg2_delta = (self.cmg2 + self.pp.g2.mul(r_delta)).into_affine();

//         Self {
//             pp: self.pp.clone(),
//             messages: self.messages.clone(),
//             r: new_r,
//             cmg1: cmg1_delta,
//             cmg2: cmg2_delta,
//         }
//     }

//     pub fn randomize_commitment_g2(&self, r_delta: &E::ScalarField) -> Self {
//         let new_r = self.r + r_delta;
//         let cmg1_delta = (self.cmg1 + self.pp.g1.mul(r_delta)).into_affine();

//         Self {
//             pp: self.pp.clone(),
//             messages: self.messages.clone(),
//             r: new_r,
//             cmg1: cmg1_delta,
//             cmg2: self.cmg2,
//         }
//     }

//     // get all exponents of the commitment, C([m_1,...,m_n],r)
//     pub fn get_exponents(&self) -> Vec<E::ScalarField> {
//         let mut exponents: Vec<E::ScalarField> = self.messages.clone();
//         exponents.push(self.r.clone());
//         exponents
//     }

//     // get pok in g1
//     pub fn prove_opening(&self) -> Result<Vec<u8>, CommitmentProofError> {
//         CommitmentProofs::pok_commitment_prove(&self)
//     }
// }

// pub fn g1_commit<E: Pairing>(
//     pp: &PublicParams<E>,
//     messages: &[E::ScalarField],
//     r: &E::ScalarField,
// ) -> E::G1Affine {
//     assert!(messages.len() <= pp.ckg1.len(), "m.len should be < ck!");
//     let ck = &pp.ckg1[..messages.len()];

//     let temp = E::G1::msm_unchecked(ck, messages);
//     let g1_r = pp.g1.mul(r);
//     temp.add(g1_r).into_affine()
// }

// pub fn g2_commit<E: Pairing>(
//     pp: &PublicParams<E>,
//     messages: &[E::ScalarField],
//     r: &E::ScalarField,
// ) -> E::G2Affine {
//     assert!(messages.len() <= pp.ckg2.len(), "message.len > ckg2.len");
//     // cut ckg2 to the size of m
//     let ck = &pp.ckg2[..messages.len()];
//     let temp = E::G2::msm_unchecked(ck, messages);
//     let g2_r = pp.g2.mul(r);
//     temp.add(g2_r).into_affine()
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ark_bls12_381::{Bls12_381, Fr};

//     #[test]
//     fn test_randomized_commitment() {
//         let mut rng = ark_std::test_rng();
//         let r = Fr::rand(&mut rng);
//         let context = Fr::rand(&mut rng);
//         let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
//         let messages: Vec<Fr> = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
//         let commitment = Commitment::new(&pp, &messages, &r);

//         let r_delta = Fr::rand(&mut rng);
//         let randomized_commitment = commitment.randomize(&r_delta);

//         let cmg1 = commitment.cmg1.add(pp.g1.mul(r_delta));
//         let cmg1_rand = randomized_commitment.cmg1;

//         let challenge = Fr::rand(&mut rng);

//         // Let's test opening proof
//         let blinding_commitment = SchnorrProtocol::commit(&pp.get_g1_bases(), &mut rng);
//         let responses = SchnorrProtocol::prove(
//             &blinding_commitment,
//             &commitment.get_exponents(),
//             &challenge,
//         );

//         let is_valid = SchnorrProtocol::verify(
//             &pp.get_g1_bases(),
//             &commitment.cmg1,
//             &blinding_commitment,
//             &responses,
//             &challenge,
//         );

//         assert!(is_valid);
//     }
// }
