use crate::keygen_coconut::{AggregatePublicKey, PartialSecretKey, ThresholdKeys};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};

#[derive(Clone, Debug)]
pub struct CoconutSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> CoconutSignature<E> {
    pub fn partial_sign(
        partial_sk: &PartialSecretKey<E>,
        h: &E::G1Affine,
        messages: &[E::ScalarField],
    ) -> Self {
        assert!(
            messages.len() == 1,
            "Coconut currently supports only one message"
        );

        let m = messages[0];
        let sigma1 = *h;
        let sigma2 = h.mul(partial_sk.x_i + m * partial_sk.y_i).into_affine();

        Self { sigma1, sigma2 }
    }

    pub fn aggregate_signatures(partial_signatures: &[Self], threshold: usize) -> Self {
        println!("partial sigs length: {}", partial_signatures.len());
        assert!(
            partial_signatures.len() >= threshold,
            "Not enough partial signatures"
        );

        let sigma1 = partial_signatures[0].sigma1; // All sigma1 are the same
                                                   // Simply sum the sigma2 values
        let mut sigma2 = E::G1::zero();

        for (i, sig) in partial_signatures.iter().take(threshold).enumerate() {
            let mut lambda_i = E::ScalarField::one();
            for (j, _) in partial_signatures.iter().take(threshold).enumerate() {
                if i != j {
                    // Calculate Lagrange coefficient
                    let i_plus_1 = E::ScalarField::from((i + 1) as u64);
                    let j_plus_1 = E::ScalarField::from((j + 1) as u64);
                    lambda_i *= j_plus_1 * (j_plus_1 - i_plus_1).neg();
                }
            }
            sigma2 += sig.sigma2.mul(lambda_i);
        }

        Self {
            sigma1,
            sigma2: sigma2.into_affine(),
        }
    }
    pub fn verify(&self, message: &E::ScalarField, aggregate_pk: &AggregatePublicKey<E>) -> bool {
        let lhs = E::pairing(self.sigma2, aggregate_pk.g2);
        let rhs = E::pairing(
            self.sigma1,
            aggregate_pk.g2_x + aggregate_pk.g2_y.mul(*message),
        );

        println!("Signature Verification:");
        println!("  sigma1: {:?}", self.sigma1);
        println!("  sigma2: {:?}", self.sigma2);
        println!("  message: {:?}", message);
        println!("  g2: {:?}", aggregate_pk.g2);
        println!("  g2_x: {:?}", aggregate_pk.g2_x);
        println!("  g2_y: {:?}", aggregate_pk.g2_y);
        println!("  LHS: {:?}", lhs);
        println!("  RHS: {:?}", rhs);

        lhs == rhs
    }

    // pub fn verify(&self, message: &E::ScalarField, aggregate_pk: &AggregatePublicKey<E>) -> bool {
    //     let lhs = E::pairing(self.sigma2, aggregate_pk.g2);
    //     let rhs = E::pairing(
    //         self.sigma1,
    //         aggregate_pk.g2_x + aggregate_pk.g2_y.mul(*message),
    //     );
    //     lhs == rhs
    // }

    pub fn randomize(&self, r: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: self.sigma2.mul(r).into_affine(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen_coconut::distributed_keygen;
    use ark_bls12_381::Bls12_381;
    use ark_ff::Field;
    use ark_std::test_rng;

    #[test]
    fn test_coconut_signature() {
        let mut rng = ark_std::test_rng();
        let n = 5;
        let t = 3;
        let message_count = 1;

        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);

        let message = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let h = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        println!("Message: {:?}", message);
        println!("h: {:?}", h);

        // Generate partial signatures
        let partial_signatures: Vec<_> = threshold_keys
            .iter()
            .map(|tk| CoconutSignature::partial_sign(&tk.partial_secret_key, &h, &[message]))
            .collect();

        // Check if partial signatures are valid
        for (i, sig) in partial_signatures.iter().enumerate() {
            let pk = &threshold_keys[i].partial_public_key;
            let lhs = Bls12_381::pairing(sig.sigma2, aggregate_pk.g2);
            let rhs = Bls12_381::pairing(sig.sigma1, pk.g2_x_i + pk.g2_y_i.mul(message));
            println!("Partial signature {} check:", i);
            println!("  sigma1: {:?}", sig.sigma1);
            println!("  sigma2: {:?}", sig.sigma2);
            println!("  g2: {:?}", aggregate_pk.g2);
            println!("  g2_x_i: {:?}", pk.g2_x_i);
            println!("  g2_y_i: {:?}", pk.g2_y_i);
            println!("  LHS: {:?}", lhs);
            println!("  RHS: {:?}", rhs);
            assert_eq!(lhs, rhs, "Partial signature {} is invalid", i);
        }

        // Aggregate signatures
        let signature = CoconutSignature::aggregate_signatures(&partial_signatures, t);

        println!("Aggregated Signature:");
        println!("  sigma1: {:?}", signature.sigma1);
        println!("  sigma2: {:?}", signature.sigma2);

        // Verify the aggregated signature
        let is_valid = signature.verify(&message, &aggregate_pk);
        println!("Aggregated signature verification result: {}", is_valid);

        assert!(is_valid, "Aggregated signature verification failed");

        // Test randomization
        let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let randomized_signature = signature.randomize(&r);

        println!("Randomized Signature:");
        println!("  sigma1: {:?}", randomized_signature.sigma1);
        println!("  sigma2: {:?}", randomized_signature.sigma2);

        let is_valid_randomized = randomized_signature.verify(&message, &aggregate_pk);
        println!(
            "Randomized signature verification result: {}",
            is_valid_randomized
        );

        assert!(
            is_valid_randomized,
            "Randomized signature verification failed"
        );
    }

    #[test]
    fn test_signature_aggregation() {
        let mut rng = ark_std::test_rng();

        // Generate some mock partial signatures
        let threshold = 3;
        let partial_signatures: Vec<CoconutSignature<Bls12_381>> = (0..threshold)
            .map(|i| {
                let sigma1 = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
                let sigma2 = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
                CoconutSignature { sigma1, sigma2 }
            })
            .collect();

        // Aggregate the signatures
        let aggregated_sig = CoconutSignature::aggregate_signatures(&partial_signatures, threshold);

        // Verify that sigma1 is the same as in all partial signatures
        assert_eq!(aggregated_sig.sigma1, partial_signatures[0].sigma1);

        // Manually compute the expected sigma2 using Lagrange interpolation
        let mut expected_sigma2 = <Bls12_381 as Pairing>::G1::zero();
        for (i, sig) in partial_signatures.iter().enumerate() {
            let mut lambda_i = <Bls12_381 as Pairing>::ScalarField::one();
            for j in 0..threshold {
                if i != j {
                    let i_plus_1 = <Bls12_381 as Pairing>::ScalarField::from((i + 1) as u64);
                    let j_plus_1 = <Bls12_381 as Pairing>::ScalarField::from((j + 1) as u64);
                    lambda_i *= j_plus_1 * (j_plus_1 - i_plus_1).neg();
                }
            }
            expected_sigma2 += sig.sigma2.mul(lambda_i);
        }
        let expected_sigma2 = expected_sigma2.into_affine();

        // Compare the aggregated sigma2 with the expected value
        assert_eq!(
            aggregated_sig.sigma2, expected_sigma2,
            "Aggregated sigma2 does not match the expected value"
        );

        println!("Aggregation Test Results:");
        println!("  Aggregated sigma1: {:?}", aggregated_sig.sigma1);
        println!("  Aggregated sigma2: {:?}", aggregated_sig.sigma2);
        println!("  Expected sigma2: {:?}", expected_sigma2);
    }

    #[test]
    fn test_distributed_key_generation() {
        let mut rng = ark_std::test_rng();
        let n = 5; // Number of parties
        let t = 3; // Threshold
        let message_count = 1; // Coconut typically uses 1 message

        // Generate keys
        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);

        // Verify the number of generated keys
        assert_eq!(
            threshold_keys.len(),
            n,
            "Incorrect number of threshold keys generated"
        );

        // Verify that all partial public keys use the same g2
        let g2 = aggregate_pk.g2;
        for key in &threshold_keys {
            assert_eq!(
                key.partial_public_key.g2_x_i.into_group(),
                g2.into_group(),
                "Inconsistent g2 in partial public keys"
            );
            assert_eq!(
                key.partial_public_key.g2_y_i.into_group(),
                g2.into_group(),
                "Inconsistent g2 in partial public keys"
            );
        }

        // Verify the relationship between secret and public keys
        for key in &threshold_keys {
            let computed_g2_x_i = g2.mul(key.partial_secret_key.x_i).into_affine();
            let computed_g2_y_i = g2.mul(key.partial_secret_key.y_i).into_affine();

            assert_eq!(
                computed_g2_x_i, key.partial_public_key.g2_x_i,
                "Mismatch in g2_x_i"
            );
            assert_eq!(
                computed_g2_y_i, key.partial_public_key.g2_y_i,
                "Mismatch in g2_y_i"
            );
        }

        // Verify that the aggregate public key is the sum of partial public keys
        let mut sum_g2_x = <Bls12_381 as Pairing>::G2::zero();
        let mut sum_g2_y = <Bls12_381 as Pairing>::G2::zero();
        for key in &threshold_keys {
            sum_g2_x += key.partial_public_key.g2_x_i;
            sum_g2_y += key.partial_public_key.g2_y_i;
        }
        assert_eq!(
            sum_g2_x.into_affine(),
            aggregate_pk.g2_x,
            "Mismatch in aggregate g2_x"
        );
        assert_eq!(
            sum_g2_y.into_affine(),
            aggregate_pk.g2_y,
            "Mismatch in aggregate g2_y"
        );

        // Verify polynomial properties
        let x_values: Vec<_> = (1..=n)
            .map(|i| <Bls12_381 as Pairing>::ScalarField::from(i as u64))
            .collect();
        let x_shares: Vec<_> = threshold_keys
            .iter()
            .map(|key| key.partial_secret_key.x_i)
            .collect();
        let y_shares: Vec<_> = threshold_keys
            .iter()
            .map(|key| key.partial_secret_key.y_i)
            .collect();

        // Check if shares lie on a polynomial of degree t-1
        assert!(
            check_polynomial_degree(&x_values, &x_shares, t - 1),
            "x shares do not lie on a polynomial of degree t-1"
        );
        assert!(
            check_polynomial_degree(&x_values, &y_shares, t - 1),
            "y shares do not lie on a polynomial of degree t-1"
        );

        println!("Distributed Key Generation Test Passed Successfully");
    }

    fn lagrange_interpolate<F: Field>(points: &[(F, F)]) -> DensePolynomial<F> {
        let mut result = DensePolynomial::zero();
        for (i, &(x_i, y_i)) in points.iter().enumerate() {
            let mut l_i = DensePolynomial::from_coefficients_vec(vec![F::one()]);
            let mut denom = F::one();

            for (j, &(x_j, _)) in points.iter().enumerate() {
                if i != j {
                    l_i = &l_i * &DensePolynomial::from_coefficients_vec(vec![-x_j, F::one()]);
                    denom *= x_i - x_j;
                }
            }

            let l_i = &l_i * y_i * denom.inverse().unwrap();
            result += &l_i;
        }
        result
    }

    // Helper function to check if points lie on a polynomial of given degree
    fn check_polynomial_degree<F: Field>(x_values: &[F], y_values: &[F], degree: usize) -> bool {
        assert_eq!(
            x_values.len(),
            y_values.len(),
            "x and y values must have the same length"
        );
        let points: Vec<_> = x_values
            .iter()
            .zip(y_values.iter())
            .map(|(&x, &y)| (x, y))
            .collect();

        let interpolated_poly = DensePolynomial::interpolate(&points).unwrap();
        interpolated_poly.degree() <= degree
    }

    #[test]
    fn test_coconut_signature2() {
        let mut rng = test_rng();
        let n = 5;
        let t = 3;
        let message_count = 1; // Coconut supports single message for now

        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);
        println!("keygen done!");

        // Generate a random message
        let message = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let h = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);

        // Generate partial signatures
        let partial_signatures: Vec<_> = threshold_keys
            .iter()
            .map(|tk| {
                let sig = CoconutSignature::partial_sign(&tk.partial_secret_key, &h, &[message]);
                println!(
                    "Partial signature for index {}: {:?}",
                    tk.partial_secret_key.index, sig
                );
                sig
            })
            .collect();
        println!("partial sigs done");

        // Check if partial signatures are valid
        for (i, sig) in partial_signatures.iter().enumerate() {
            let lhs = Bls12_381::pairing(sig.sigma2, aggregate_pk.g2);
            let rhs = Bls12_381::pairing(
                sig.sigma1,
                aggregate_pk.g2_x + aggregate_pk.g2_y.mul(message),
            );
            println!("Partial signature {} check:", i);
            println!("  LHS: {:?}", lhs);
            println!("  RHS: {:?}", rhs);
            assert_eq!(lhs, rhs, "Partial signature {} is invalid", i);
            println!("Partial signature {} is valid", i);
        }

        // Aggregate signatures
        let signature = CoconutSignature::aggregate_signatures(&partial_signatures, t);

        // Verify the signature
        assert!(signature.verify(&message, &aggregate_pk));
        println!("signature verified");
        // Test randomization
        let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let randomized_signature = signature.randomize(&r);
        assert!(randomized_signature.verify(&message, &aggregate_pk));
    }
}
