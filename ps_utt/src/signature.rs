// // Set this up with the Prover, Issuer, Verifier
// // Issuance is between Issuer and Prover
// // Verification is between Verifier and Prover
// // Where are public parameters stored?
// // A user with multiple signatures will need to prove knowledge of each, then use the responses from each together
// // Each credential has a signature with randomization, a commitment with randomization, public params, zkp operations
// // The verifier for any credential will receive as input (randomized credential, randomized commitment, public parameters, zero knowledge proof)
// // The issuer for a specific credential will receive (commitment, public parameters, zero knowledge proof). Will sign the commitment with respect to commitment, public params and zkp)

// use ark_ec::pairing::Pairing;
// use ark_ec::{AffineRepr, CurveGroup};
// use ark_ff::UniformRand;
// use ark_std::rand::Rng;
// use ark_std::{
//     ops::{Add, Mul, Neg},
//     One, Zero,
// };
// use utils::helpers::Helpers;

// pub struct PublicParams<E: Pairing> {
//     pub h1: E::G1Affine,
//     pub h2: E::G2Affine,
//     pub g1_y: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
//     pub g2_y: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
//     pub g2_x: E::G2Affine,
// }

// #[derive(Clone, Debug)]
// pub struct PSSigningKey<E: Pairing> {
//     pub sk: E::G1Affine, // g1^x
// }

// pub struct PSScheme<E: Pairing> {
//     pub params: PublicParams<E>,
//     pub signing_key: PSSigningKey<E>,
// }

// #[derive(Clone, Debug)]
// pub struct Commitment<E: Pairing> {
//     pub m: Vec<E::ScalarField>,
//     pub r: E::ScalarField,
//     pub g1_cm: E::G1Affine,
//     pub g2_cm: E::G2Affine,
// }

// pub struct PSSignature<E: Pairing> {
//     pub sigma1: E::G1Affine,
//     pub sigma2: E::G1Affine,
//     pub commitment: Commitment<E>,
// }

// impl<E: Pairing> Commitment<E> {
//     fn new(messages: Vec<E::ScalarField>, r: E::ScalarField, params: &PublicParams<E>) -> Self {
//         let g1_cm = Helpers::commit_g1::<E>(&r, &messages, &params.g1_y, &params.h1);
//         let g2_cm = Helpers::commit_g2::<E>(&r, &messages, &params.g2_y, &params.h2);

//         Self {
//             m: messages,
//             r,
//             g1_cm,
//             g2_cm,
//         }
//     }

//     // pub fn rerandomize(&self, ck: &CommitmentKey<E>, delta_r: E::ScalarField) -> Self {
//     //     let g1_randomized = ck.h1.mul(delta_r).add(self.g1_cm).into_affine();
//     //     let g2_randomized = ck.h2.mul(delta_r).add(self.g2_cm).into_affine();
//     //     let r_prime = self.r + delta_r;

//     //     Self {
//     //         messages: self.messages.clone(),
//     //         r: r_prime,
//     //         g1_cm: g1_randomized,
//     //         g2_cm: g2_randomized,
//     //     }
// }

// // This is the for example registration authority. Sets up, receives a request to sign and returns a credential
// impl<E: Pairing> PSScheme<E> {
//     pub fn setup<R: Rng>(message_count: usize, rng: &mut R) -> Self {
//         Self {
//             params,
//             signing_key,
//         }
//     }

//     pub fn sign(&self, commitment: &Commitment<E>) -> PSSignature<E> {
//         // Create signature...
//     }

//     pub fn blind_sign(&self, commitment: &Commitment<E>) -> PSSignature<E> {
//         // Create blind signature...
//     }
// }

// // #[derive(Clone, Debug)]
// // pub struct PublicParams<E: Pairing> {
// //     pub h1: E::G1Affine,
// //     pub h2: E::G2Affine,
// //     pub g1_y: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
// //     pub g2_y: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
// // }

// // struct PSSignature<E: Pairing> {
// //     sigma1: E::G1Affine,  //
// //     sigma2: E::G1Affine,  //
// //     commitment: Commitment<E>  // The commitment being signed
// // }

// // impl<E: Pairing> CommitmentScheme<E> {
// //     pub fn setup<R: Rng>(m_count: usize, rng: &mut R) -> Self {
// //         let h1 = E::G1Affine::rand(rng);
// //         let h2 = E::G2Affine::rand(rng);
// //         let yi: Vec<E::ScalarField> = (0..m_count).map(|_| E::ScalarField::rand(rng)).collect();

// //         let g1_y = E::G1::normalize_batch(&yi.iter().map(|yi| h1.mul(*yi)).collect::<Vec<_>>());
// //         let g2_y = E::G2::normalize_batch(&yi.iter().map(|yi| h2.mul(*yi)).collect::<Vec<_>>());

// //         Self {
// //             ck: CommitmentKey { h1, h2, g1_y, g2_y },
// //         }
// //     }

// //     pub fn commit(&self, messages: &[E::ScalarField], r: E::ScalarField) -> Commitment<E> {
// //         Commitment::new(messages.to_vec(), r, &self.ck)
// //     }

// //     // Verify G1 G2 Pairing Consistency
// //     pub fn verify_commitment(&self, commitment: &Commitment<E>) -> bool {
// //         // Verify commitment consistency using pairing
// //         let pairing1 = E::pairing(commitment.g1_cm, self.ck.h2);
// //         let pairing2 = E::pairing(self.ck.h1, commitment.g2_cm);
// //         pairing1 == pairing2
// //     }
// // }

// // // Individual commitment instance
// // pub struct Commitment<E: Pairing> {
// //     messages: Vec<E::ScalarField>,
// //     r: E::ScalarField,
// //     pub g1_cm: E::G1Affine,
// //     pub g2_cm: E::G2Affine,
// // }

// // impl<E: Pairing> Commitment<E> {
// //     fn new(messages: Vec<E::ScalarField>, r: E::ScalarField, ck: &CommitmentKey<E>) -> Self {
// //         let g1_cm = Helpers::commit_g1::<E>(&r, &messages, &ck.g1_y, &ck.h1);
// //         let g2_cm = Helpers::commit_g2::<E>(&r, &messages, &ck.g2_y, &ck.h2);

// //         Self {
// //             messages,
// //             r,
// //             g1_cm,
// //             g2_cm,
// //         }
// //     }

// //     pub fn rerandomize(&self, ck: &CommitmentKey<E>, delta_r: E::ScalarField) -> Self {
// //         let g1_randomized = ck.h1.mul(delta_r).add(self.g1_cm).into_affine();
// //         let g2_randomized = ck.h2.mul(delta_r).add(self.g2_cm).into_affine();
// //         let r_prime = self.r + delta_r;

// //         Self {
// //             messages: self.messages.clone(),
// //             r: r_prime,
// //             g1_cm: g1_randomized,
// //             g2_cm: g2_randomized,
// //         }
// //     }
// // }

// // // PS Signature scheme that works with commitments
// // pub struct PSSignatureScheme<E: Pairing> {
// //     pub commitment_scheme: CommitmentScheme<E>,
// //     pub sk: E::G1Affine,
// //     pub vk: E::G2Affine,
// // }

// // pub struct PSSignature<E: Pairing> {
// //     pub sigma1: E::G1Affine,
// //     pub sigma2: E::G1Affine,
// //     pub commitment: Commitment<E>,
// // }

// // impl<E: Pairing> PSSignatureScheme<E> {
// //     pub fn setup<R: Rng>(m_count: usize, rng: &mut R) -> Self {
// //         let commitment_scheme = CommitmentScheme::<E>::setup(m_count, rng);
// //         let x = E::ScalarField::rand(rng);
// //         let sk = commitment_scheme.ck.h1.mul(x).into_affine();
// //         let vk = commitment_scheme.ck.h2.mul(x).into_affine();

// //         Self {
// //             commitment_scheme,
// //             sk,
// //             vk,
// //         }
// //     }

// //     pub fn sign(&self, commitment: &Commitment<E>) -> Signature<E> {
// //         let u = E::ScalarField::rand(&mut ark_std::rand::thread_rng());
// //         let sigma1 = self.commitment_scheme.ck.h1.mul(u).into_affine();
// //         let sigma2 = (self.sk.add(commitment.g1_cm)).mul(u).into_affine();

// //         Signature { sigma1, sigma2 }
// //     }

// //     pub fn verify(&self, signature: &Signature<E>, commitment: &Commitment<E>) -> bool {
// //         let pairing1 = E::pairing(signature.sigma2, self.commitment_scheme.ck.h2);
// //         let pairing2 = E::pairing(
// //             signature.sigma1,
// //             self.vk.add(commitment.g2_cm).into_affine(),
// //         );
// //         pairing1 == pairing2
// //     }
// // }

// // #[cfg(test)]
// // mod tests {
// //     use super::*;
// //     use ark_bls12_381::{Bls12_381, Fr};
// //     use ark_std::rand::thread_rng;
// //     use ark_std::UniformRand;

// //     type E = Bls12_381;

// //     #[test]
// //     fn test_commitment_scheme_operations() {
// //         let mut rng = thread_rng();
// //         let m_count = 3;

// //         // Setup commitment scheme
// //         let scheme = CommitmentScheme::<E>::setup(m_count, &mut rng);

// //         // Create random messages
// //         let messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
// //         let r = Fr::rand(&mut rng);

// //         // Create commitment
// //         let commitment = scheme.commit(&messages, r);

// //         // Test 1: Verify commitment consistency
// //         assert!(
// //             scheme.verify_commitment(&commitment),
// //             "Commitment verification failed"
// //         );

// //         // Test 2: Rerandomization
// //         let delta_r = Fr::rand(&mut rng);
// //         let rerandomized_commitment = commitment.rerandomize(&scheme.ck, delta_r);

// //         // Verify rerandomized commitment is still valid
// //         assert!(
// //             scheme.verify_commitment(&rerandomized_commitment),
// //             "Rerandomized commitment verification failed"
// //         );

// //         // Test 3: Different randomness produces different commitments
// //         let r2 = Fr::rand(&mut rng);
// //         let commitment2 = scheme.commit(&messages, r2);
// //         assert_ne!(
// //             commitment.g1_cm, commitment2.g1_cm,
// //             "Different randomness should produce different commitments"
// //         );

// //         // Test 4: Same messages and randomness produce same commitment
// //         let commitment3 = scheme.commit(&messages, r);
// //         assert_eq!(
// //             commitment.g1_cm, commitment3.g1_cm,
// //             "Same messages and randomness should produce same commitment"
// //         );
// //     }

// //     #[test]
// //     fn test_ps_signature_operations() {
// //         let mut rng = thread_rng();
// //         let m_count = 3;

// //         // Setup PS signature scheme
// //         let ps_scheme = PSSignatureScheme::<E>::setup(m_count, &mut rng);

// //         // Create a commitment to sign
// //         let messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
// //         let r = Fr::rand(&mut rng);
// //         let commitment = ps_scheme.commitment_scheme.commit(&messages, r);

// //         // Test 1: Sign and verify
// //         let signature = ps_scheme.sign(&commitment);
// //         assert!(
// //             ps_scheme.verify(&signature, &commitment),
// //             "Signature verification failed"
// //         );

// //         // Test 2: Verify signature fails with different commitment
// //         let different_messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
// //         let different_commitment = ps_scheme
// //             .commitment_scheme
// //             .commit(&different_messages, Fr::rand(&mut rng));
// //         assert!(
// //             !ps_scheme.verify(&signature, &different_commitment),
// //             "Signature verification should fail with different commitment"
// //         );

// //         // Test 3: Verify signature with rerandomized commitment
// //         let delta_r = Fr::rand(&mut rng);
// //         let rerandomized_commitment =
// //             commitment.rerandomize(&ps_scheme.commitment_scheme.ck, delta_r);
// //         let signature_rerandomized = ps_scheme.sign(&rerandomized_commitment);
// //         assert!(
// //             ps_scheme.verify(&signature_rerandomized, &rerandomized_commitment),
// //             "Signature verification failed for rerandomized commitment"
// //         );

// //         // Test 4: Different signers produce different signatures
// //         let ps_scheme2 = PSSignatureScheme::<E>::setup(m_count, &mut rng);
// //         let signature2 = ps_scheme2.sign(&commitment);
// //         assert_ne!(
// //             signature.sigma1, signature2.sigma1,
// //             "Different signers should produce different signatures"
// //         );
// //     }
// // }
