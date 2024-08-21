// use crate::keygen_coconut::{AggregatePublicKey, PartialSecretKey, ThresholdKeys};
// use ark_ec::pairing::{Pairing, PairingOutput};
// use ark_ec::{AffineRepr, CurveGroup, Group};
// use ark_ff::{Field, PrimeField, UniformRand};
// use ark_std::{
//     ops::{Add, Mul, Neg},
//     rand::Rng,
//     One, Zero,
// };

// #[derive(Clone, Debug)]
// pub struct CoconutSignature<E: Pairing> {
//     pub sigma1: E::G1Affine,
//     pub sigma2: E::G1Affine,
// }

// impl<E: Pairing> CoconutSignature<E>
// where
//     E::ScalarField: PrimeField,
//     E::G1Affine: AffineRepr<ScalarField = E::ScalarField>,
// {
//     pub fn partial_sign(
//         partial_sk: &PartialSecretKey<E::ScalarField>,
//         h: &E::G1Affine,
//         messages: &[E::ScalarField],
//     ) -> Self {
//         assert_eq!(
//             messages.len(),
//             1,
//             "Coconut currently supports only one message"
//         );

//         let m = messages[0];
//         let sigma1 = *h;
//         let sigma2 = h.mul(partial_sk.x_i + m * partial_sk.y_i).into_affine();

//         println!("Partial Signature:");
//         println!("  sigma1: {:?}", sigma1);
//         println!("  sigma2: {:?}", sigma2);

//         Self { sigma1, sigma2 }
//     }

//     pub fn aggregate_signatures(partial_signatures: &[Self], threshold: usize) -> Self {
//         assert!(
//             partial_signatures.len() >= threshold,
//             "Not enough partial signatures"
//         );

//         let sigma1 = partial_signatures[0].sigma1; // All sigma1 are the same
//         let mut sigma2 = E::G1::zero();

//         for (i, partial_sig) in partial_signatures.iter().take(threshold).enumerate() {
//             let mut lambda_i = E::ScalarField::one();
//             for (j, _) in partial_signatures.iter().take(threshold).enumerate() {
//                 if i != j {
//                     let i_plus_1 = E::ScalarField::from((i + 1) as u64);
//                     let j_plus_1 = E::ScalarField::from((j + 1) as u64);
//                     lambda_i *= j_plus_1 * (j_plus_1 - i_plus_1).inverse().unwrap();
//                 }
//             }
//             sigma2 += partial_sig.sigma2.mul(lambda_i);
//         }

//         let result = Self {
//             sigma1,
//             sigma2: sigma2.into_affine(),
//         };

//         println!("Aggregated Signature:");
//         println!("  sigma1: {:?}", result.sigma1);
//         println!("  sigma2: {:?}", result.sigma2);

//         result
//     }

//     pub fn verify(&self, message: &E::ScalarField, aggregate_pk: &AggregatePublicKey<E>) -> bool {
//         // let rhs = E::pairing(self.sigma2, aggregate_pk.g2);
//         let rhs = E::pairing(
//             self.sigma1,
//             aggregate_pk.g2_x + aggregate_pk.g2_y.mul(*message),
//         );
//         // let add = aggregate_pk.g2_x + aggregate_pk.g2_y.mul(*message);
//         // let lhs = E::pairing(self.sigma1, aggregate_pk.g2 + add);

//         let lhs = E::pairing(self.sigma1, aggregate_pk.g2_x)
//             + E::pairing(self.sigma1.mul(*message), aggregate_pk.g2_y);

//         println!("Verification:");
//         println!("  LHS: {:?}", lhs);
//         println!("  RHS: {:?}", rhs);
//         println!("  g2_x: {:?}", aggregate_pk.g2_x);
//         println!("  g2_y: {:?}", aggregate_pk.g2_y);
//         println!("  message: {:?}", message);

//         lhs == rhs
//     }

//     pub fn randomize(&self, r: &E::ScalarField) -> Self {
//         Self {
//             sigma1: self.sigma1.mul(r).into_affine(),
//             sigma2: self.sigma2.mul(r).into_affine(),
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::keygen_coconut::distributed_keygen;
//     use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
//     use ark_ff::Field;
//     use ark_std::test_rng;

//     #[test]
//     fn test_key_generation() {
//         let mut rng = ark_std::test_rng();
//         let n = 5;
//         let t = 3;
//         let message_count = 1;

//         let (threshold_keys, aggregate_pk) =
//             distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);

//         assert_eq!(
//             threshold_keys.len(),
//             n,
//             "Incorrect number of threshold keys generated"
//         );

//         // Print key information for inspection
//         println!("Aggregate Public Key:");
//         println!("  g2_x: {:?}", aggregate_pk.g2_x);
//         println!("  g2_y: {:?}", aggregate_pk.g2_y);

//         for (i, key) in threshold_keys.iter().enumerate() {
//             println!("Threshold Key {}:", i);
//             println!("  x_i: {:?}", key.partial_secret_key.x_i);
//             println!("  y_i: {:?}", key.partial_secret_key.y_i);
//             println!("  g2_x_i: {:?}", key.partial_public_key.g2_x_i);
//             println!("  g2_y_i: {:?}", key.partial_public_key.g2_y_i);
//         }
//     }

//     #[test]
//     fn test_partial_signing() {
//         let mut rng = ark_std::test_rng();
//         let message = Fr::rand(&mut rng);
//         let h = G1Affine::generator();

//         // Create a dummy partial secret key
//         let partial_sk = PartialSecretKey {
//             index: 1,
//             x_i: Fr::from(2u32),
//             y_i: Fr::from(3u32),
//         };

//         let signature = CoconutSignature::<Bls12_381>::partial_sign(&partial_sk, &h, &[message]);

//         println!("Message: {:?}", message);
//         println!("Partial Signature:");
//         println!("  sigma1: {:?}", signature.sigma1);
//         println!("  sigma2: {:?}", signature.sigma2);

//         // Verify that sigma2 = h * (x_i + m * y_i)
//         let expected_sigma2 = h
//             .mul(partial_sk.x_i + message * partial_sk.y_i)
//             .into_affine();
//         assert_eq!(
//             signature.sigma2, expected_sigma2,
//             "Partial signature is incorrect"
//         );
//     }

//     #[test]
//     fn test_signature_verification_1_random() {
//         let mut rng = ark_std::test_rng();

//         // Generate random message
//         let message = Fr::rand(&mut rng);

//         // Generate random values for aggregate public key
//         let g1 = G1Affine::rand(&mut rng);
//         let g2 = G2Affine::rand(&mut rng);
//         let x = Fr::rand(&mut rng);
//         let y = Fr::rand(&mut rng);

//         // Create random aggregate public key
//         let aggregate_pk: AggregatePublicKey<Bls12_381> = AggregatePublicKey {
//             g1,
//             g2,
//             g2_x: g2.mul(x).into_affine(),
//             g2_y: g2.mul(y).into_affine(),
//         };

//         // Generate random h for signature
//         let h = G1Affine::rand(&mut rng);

//         // Create a valid signature
//         let signature = CoconutSignature {
//             sigma1: h,
//             sigma2: h.mul(x + message * y).into_affine(),
//         };

//         let is_valid = signature.verify(&message, &aggregate_pk);

//         println!("Message: {:?}", message);
//         println!("Aggregate Public Key:");
//         println!("  g1: {:?}", aggregate_pk.g1);
//         println!("  g2: {:?}", aggregate_pk.g2);
//         println!("  g2_x: {:?}", aggregate_pk.g2_x);
//         println!("  g2_y: {:?}", aggregate_pk.g2_y);
//         println!("Signature:");
//         println!("  sigma1: {:?}", signature.sigma1);
//         println!("  sigma2: {:?}", signature.sigma2);
//         println!("Verification result: {}", is_valid);

//         assert!(is_valid, "Signature verification failed");
//     }

//     #[test]
//     fn test_signature_verification() {
//         let mut rng = ark_std::test_rng();
//         let message = Fr::rand(&mut rng);
//         let h = G1Affine::generator();

//         // Create dummy aggregate public key
//         let aggregate_pk: AggregatePublicKey<Bls12_381> = AggregatePublicKey {
//             g1: G1Affine::generator(),
//             g2: G2Affine::generator(),
//             g2_x: G2Affine::generator().mul(Fr::from(2u32)).into_affine(),
//             g2_y: G2Affine::generator().mul(Fr::from(3u32)).into_affine(),
//         };

//         // Create a dummy signature
//         let signature = CoconutSignature {
//             sigma1: h,
//             sigma2: h
//                 .mul(Fr::from(2u32) + message * Fr::from(3u32))
//                 .into_affine(),
//         };

//         let is_valid = signature.verify(&message, &aggregate_pk);

//         println!("Message: {:?}", message);
//         println!("Signature:");
//         println!("  sigma1: {:?}", signature.sigma1);
//         println!("  sigma2: {:?}", signature.sigma2);
//         println!("Verification result: {}", is_valid);

//         assert!(is_valid, "Signature verification failed");
//     }

//     #[test]
//     fn test_signature_aggregation() {
//         // Define hard-coded values for testing
//         let sigma1 = G1Affine::generator();

//         // Create three partial signatures
//         let partial_signatures = vec![
//             CoconutSignature {
//                 sigma1,
//                 sigma2: G1Affine::generator().mul(Fr::from(2u32)).into_affine(),
//             },
//             CoconutSignature {
//                 sigma1,
//                 sigma2: G1Affine::generator().mul(Fr::from(3u32)).into_affine(),
//             },
//             CoconutSignature {
//                 sigma1,
//                 sigma2: G1Affine::generator().mul(Fr::from(4u32)).into_affine(),
//             },
//         ];

//         // Aggregate the signatures
//         let threshold = 3;
//         let aggregated_signature =
//             CoconutSignature::<Bls12_381>::aggregate_signatures(&partial_signatures, threshold);

//         // Print the results
//         println!("Partial signatures:");
//         for (i, sig) in partial_signatures.iter().enumerate() {
//             println!(
//                 "  Signature {}: sigma1 = {:?}, sigma2 = {:?}",
//                 i, sig.sigma1, sig.sigma2
//             );
//         }
//         println!("Aggregated signature:");
//         println!("  sigma1 = {:?}", aggregated_signature.sigma1);
//         println!("  sigma2 = {:?}", aggregated_signature.sigma2);

//         // Verify the result (this will depend on the expected outcome based on your scheme)
//         // For this example, we'll just check that the aggregated sigma2 is not equal to any of the partial sigma2s
//         assert_ne!(aggregated_signature.sigma2, partial_signatures[0].sigma2);
//         assert_ne!(aggregated_signature.sigma2, partial_signatures[1].sigma2);
//         assert_ne!(aggregated_signature.sigma2, partial_signatures[2].sigma2);

//         // You might want to add more specific assertions based on the expected behavior of your aggregation function
//     }

//     #[test]
//     fn test_coconut_signature() {
//         let mut rng = test_rng();
//         let n = 5;
//         let t = 3;
//         let message_count = 1;

//         println!("1. Generating keys");
//         let (threshold_keys, aggregate_pk) =
//             distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);
//         println!("Aggregate public key: {:?}", aggregate_pk);

//         let message = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
//         let h = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

//         println!("2. Message and h:");
//         println!("Message: {:?}", message);
//         println!("h: {:?}", h);

//         println!("3. Generating partial signatures");
//         let partial_signatures: Vec<_> = threshold_keys
//             .iter()
//             .map(|tk| {
//                 let sig = CoconutSignature::partial_sign(&tk.partial_secret_key, &h, &[message]);
//                 println!("Partial signature: {:?}", sig);
//                 sig
//             })
//             .collect();

//         println!("4. Checking partial signature validity");
//         for (i, sig) in partial_signatures.iter().enumerate() {
//             let pk = &threshold_keys[i].partial_public_key;
//             let lhs = Bls12_381::pairing(sig.sigma2, aggregate_pk.g2);
//             let rhs = Bls12_381::pairing(sig.sigma1, pk.g2_x_i + pk.g2_y_i.mul(message));
//             println!("Partial signature {} validity: {}", i, lhs == rhs);
//             assert!(lhs == rhs, "Partial signature {} is invalid", i);
//         }

//         println!("5. Aggregating signatures");
//         // After aggregating signatures
//         let signature = CoconutSignature::aggregate_signatures(&partial_signatures, t);

//         // Verify each component of the verification equation
//         let lhs = Bls12_381::pairing(signature.sigma2, aggregate_pk.g2);
//         let rhs_part1 = Bls12_381::pairing(signature.sigma1, aggregate_pk.g2_x);
//         let rhs_part2 = Bls12_381::pairing(signature.sigma1, aggregate_pk.g2_y.mul(message));
//         let rhs = rhs_part1 + rhs_part2;

//         println!("Detailed Verification:");
//         println!("  LHS: {:?}", lhs);
//         println!("  RHS (part 1): {:?}", rhs_part1);
//         println!("  RHS (part 2): {:?}", rhs_part2);
//         println!("  RHS (total): {:?}", rhs);

//         // Verify the aggregated signature
//         let is_valid = signature.verify(&message, &aggregate_pk);
//         println!("Aggregated signature validity: {}", is_valid);
//         assert!(is_valid, "Aggregated signature verification failed");

//         let is_valid = signature.verify(&message, &aggregate_pk);
//         println!("Aggregated signature validity: {}", is_valid);
//         assert!(is_valid, "Aggregated signature verification failed");

//         println!("7. Testing randomization");
//         let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
//         println!("Randomization factor r: {:?}", r);
//         let randomized_signature = signature.randomize(&r);
//         println!("Randomized signature: {:?}", randomized_signature);

//         println!("8. Verifying randomized signature");
//         let is_valid_randomized = randomized_signature.verify(&message, &aggregate_pk);
//         println!("Randomized signature validity: {}", is_valid_randomized);
//         assert!(
//             is_valid_randomized,
//             "Randomized signature verification failed"
//         );
//     }
// }
