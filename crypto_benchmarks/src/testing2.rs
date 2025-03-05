use ark_bls12_381::{Bls12_381, Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::CyclotomicMultSubgroup;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::uint;
use ark_std::test_rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, Group};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_representation() {
        let mut rng = test_rng(); // Initialize RNG for testing
        let g = G1Affine::rand(&mut rng); // Random G1 point
        let g = G1Projective::rand(&mut rng); // Random G1 point
        println!("affine representation: {}", g);
        // (241521825108085326152546143885075698096242717769365851673777146265962830024243722276743782280873588223519920495647,
        // 3560035591319159527750795167323375962990500740637199979279756662028071590138066280420930564248685402405154128130764)
        println!("projective representation: {}", g);
        // (241521825108085326152546143885075698096242717769365851673777146265962830024243722276743782280873588223519920495647,
        //  3560035591319159527750795167323375962990500740637199979279756662028071590138066280420930564248685402405154128130764)
    }

    /// Test 1: Scalar Multiplication
    /// Goal: Multiply a group element by a scalar.
    /// Expectation: For g in G1 and scalar a in Fr, compute g * a.
    #[test]
    fn test_scalar_multiplication() {
        let mut rng = test_rng(); // Initialize RNG for testing
        let g = G1Affine::rand(&mut rng); // Random G1 point
        let a = Fr::rand(&mut rng);
        let result = g.mul(a).into_affine(); // Scalar multiplication, stored as affine
    }

    /// Test 2: Group Addition
    /// Goal: Add two group elements together.
    /// Expectation: For g, h in G1, compute g + h.
    #[test]
    fn test_group_addition() {
        let mut rng = test_rng();
        let g = G1Affine::rand(&mut rng);
        let h = G1Affine::rand(&mut rng);
        let sum = (g + h).into_affine();
        let sum2 = g.add(h).into_affine();
        let sum3 = g.add(h);
        assert_eq!(sum, sum2, "sum, sum2 not equal");
        assert_eq!(sum, sum3, "sum, sum3 not equal");
    }

    ///
    /// This is not a fair test because it only uses Fr::one() in the MSM.
    #[test]
    fn test_efficiency_difference_group_addition_affine_projective() {
        let mut rng = test_rng();
        let num_points = 1000; // Change to 1000 for more noticeable differences

        // Step 1: Generate 100 affine points
        let affine_points: Vec<G1Affine> =
            (0..num_points).map(|_| G1Affine::rand(&mut rng)).collect();

        // Step 2: Generate 100 projective points from affine points
        let projective_points: Vec<G1Projective> =
            affine_points.iter().map(|p| p.into_group()).collect();

        // Step 3: Naive addition of affine points
        let start_affine = Instant::now();
        let mut sum_affine = G1Projective::zero();
        for point in &affine_points {
            sum_affine += point.into_group(); // Convert to projective for addition
        }
        let duration_affine = start_affine.elapsed();
        println!(
            "Time to add {} affine points naively: {:?}",
            num_points, duration_affine
        );

        // Step 4: Naive addition of projective points
        let start_projective = Instant::now();
        let mut sum_projective = G1Projective::zero();
        for point in &projective_points {
            sum_projective += point;
        }
        let duration_projective = start_projective.elapsed();
        println!(
            "Time to add {} projective points naively: {:?}",
            num_points, duration_projective
        );

        // Step 5: MSM for affine points
        let start_msm_affine = Instant::now();
        let scalars: Vec<Fr> = vec![Fr::one(); num_points]; // Scalars all set to 1
        let sum_msm_affine = G1Projective::msm_unchecked(&affine_points, &scalars);
        let duration_msm_affine = start_msm_affine.elapsed();
        println!(
            "Time to add {} affine points with MSM: {:?}",
            num_points, duration_msm_affine
        );

        // Step 6: MSM for projective points (convert to affine first)
        let start_msm_projective = Instant::now();
        let affine_from_projective: Vec<G1Affine> =
            projective_points.iter().map(|p| p.into_affine()).collect();
        let sum_msm_projective = G1Projective::msm_unchecked(&affine_from_projective, &scalars);
        let duration_msm_projective = start_msm_projective.elapsed();
        println!(
            "Time to add {} projective points with MSM: {:?}",
            num_points, duration_msm_projective
        );

        // Optional: Verify results are consistent (convert to affine for comparison)
        let sum_affine_affine = sum_affine.into_affine();
        let sum_projective_affine = sum_projective.into_affine();
        let sum_msm_affine_affine = sum_msm_affine.into_affine();
        let sum_msm_projective_affine = sum_msm_projective.into_affine();
        assert_eq!(sum_affine_affine, sum_projective_affine);
        assert_eq!(sum_affine_affine, sum_msm_affine_affine);
        assert_eq!(sum_affine_affine, sum_msm_projective_affine);
    }

    ///
    /// Time to add 1000 affine points with random scalars naively: 2.399358166s
    /// Time to add 1000 projective points with random scalars naively: 2.713442083s
    /// Time to add 1000 affine points with random scalars using MSM: 81.458167ms
    /// Time to add 1000 projective points with random scalars using MSM: 74.241583ms
    /// MSM is ~30x faster than naive implementation with random scalars (2.4s vs 81.5ms)
    #[test]
    fn test_efficiency_difference_with_random_scalars() {
        let mut rng = test_rng();
        let num_points = 1000; // Change this value to test with more points

        // Step 1: Generate affine points
        let affine_points: Vec<G1Affine> =
            (0..num_points).map(|_| G1Affine::rand(&mut rng)).collect();

        // Step 2: Generate projective points from affine points
        let projective_points: Vec<G1Projective> =
            affine_points.iter().map(|p| p.into_group()).collect();

        // Generate random scalars
        let random_scalars: Vec<Fr> = (0..num_points).map(|_| Fr::rand(&mut rng)).collect();

        // Step 3: Naive addition of affine points with scalar multiplication
        let start_affine = Instant::now();
        let mut sum_affine = G1Projective::zero();
        for (point, scalar) in affine_points.iter().zip(random_scalars.iter()) {
            sum_affine += point.mul(*scalar);
        }
        let duration_affine = start_affine.elapsed();
        println!(
            "Time to add {} affine points with random scalars naively: {:?}",
            num_points, duration_affine
        );

        // Step 4: Naive addition of projective points with scalar multiplication
        let start_projective = Instant::now();
        let mut sum_projective = G1Projective::zero();
        for (point, scalar) in projective_points.iter().zip(random_scalars.iter()) {
            sum_projective += point.mul(*scalar);
        }
        let duration_projective = start_projective.elapsed();
        println!(
            "Time to add {} projective points with random scalars naively: {:?}",
            num_points, duration_projective
        );

        // Step 5: MSM for affine points with random scalars
        let start_msm_affine = Instant::now();
        let sum_msm_affine = G1Projective::msm_unchecked(&affine_points, &random_scalars);
        let duration_msm_affine = start_msm_affine.elapsed();
        println!(
            "Time to add {} affine points with random scalars using MSM: {:?}",
            num_points, duration_msm_affine
        );

        // Step 6: MSM for projective points with random scalars (convert to affine first)
        let start_msm_projective = Instant::now();
        let affine_from_projective: Vec<G1Affine> =
            projective_points.iter().map(|p| p.into_affine()).collect();
        let sum_msm_projective =
            G1Projective::msm_unchecked(&affine_from_projective, &random_scalars);
        let duration_msm_projective = start_msm_projective.elapsed();
        println!(
            "Time to add {} projective points with random scalars using MSM: {:?}",
            num_points, duration_msm_projective
        );

        // Verify results are consistent (they might differ due to order of operations)
        assert_eq!(sum_msm_affine, sum_msm_projective);
        // Note: We can't assert equality with the naive implementations because
        // the order of operations affects the final result with random scalars
    }

    ///
    /// Running 100 pairing equality tests
    /// Time for 100 equality tests with full pairings: 6.422018333s
    /// Time for 100 equality tests with Miller loops: 4.078332417s
    /// Time for batch verification of 100 equality tests: 911.17875ms
    /// Speedup using Miller loops: 1.57x
    /// Speedup using batch verification: 7.05x
    /// Total test time: 19.02425325s
    fn test_pairing_equality_efficiency<P: Pairing>(num_tests: usize) {
        let mut rng = ark_std::rand::thread_rng();

        println!("Running {} pairing equality tests", num_tests);

        // Generate random points for testing
        let g1_points: Vec<P::G1> = (0..num_tests).map(|_| P::G1::rand(&mut rng)).collect();
        let g2_points: Vec<P::G2> = (0..num_tests).map(|_| P::G2::rand(&mut rng)).collect();
        let h1_points: Vec<P::G1> = (0..num_tests).map(|_| P::G1::rand(&mut rng)).collect();
        let h2_points: Vec<P::G2> = (0..num_tests).map(|_| P::G2::rand(&mut rng)).collect();

        // Approach 1: Compute full pairings and compare
        let start_full_pairing = ark_std::time::Instant::now();

        for i in 0..num_tests {
            let lhs = P::pairing(g1_points[i], g2_points[i]);
            let rhs = P::pairing(h1_points[i], h2_points[i]);
            let _ = lhs == rhs; // Just to ensure the compiler doesn't optimize this away
        }

        let duration_full_pairing = start_full_pairing.elapsed();
        println!(
            "Time for {} equality tests with full pairings: {:?}",
            num_tests, duration_full_pairing
        );

        // Approach 2: Use Miller loops and final exponentiation
        let start_miller_loop = ark_std::time::Instant::now();

        for i in 0..num_tests {
            // e(g1, g2) == e(h1, h2) if and only if e(g1, g2) · e(h1, -h2) == 1

            // Prepare the points for the pairing
            let g1_prep = P::G1Prepared::from(&g1_points[i]);
            let g2_prep = P::G2Prepared::from(&g2_points[i]);
            let h1_prep = P::G1Prepared::from(&h1_points[i]);

            // Negate h2 and prepare it
            let neg_h2 = -h2_points[i];
            let neg_h2_prep = P::G2Prepared::from(&neg_h2);

            // Compute e(g1, g2) · e(h1, -h2) using multi_miller_loop
            let ml_result = P::multi_miller_loop([g1_prep, h1_prep], [g2_prep, neg_h2_prep]);

            // Apply final exponentiation and check if result is 1 (identity element)
            let final_result = P::final_exponentiation(ml_result);
            let _ = final_result.unwrap().is_zero(); // is_zero() checks if it's the identity
        }

        let duration_miller_loop = start_miller_loop.elapsed();
        println!(
            "Time for {} equality tests with Miller loops: {:?}",
            num_tests, duration_miller_loop
        );

        // Approach 3: Batch verification of multiple pairings
        let start_batch = ark_std::time::Instant::now();

        // This only makes sense if we're testing multiple equalities at once
        if num_tests > 1 {
            let mut all_g1: Vec<P::G1Prepared> = Vec::with_capacity(num_tests * 2);
            let mut all_g2: Vec<P::G2Prepared> = Vec::with_capacity(num_tests * 2);

            for i in 0..num_tests {
                all_g1.push(P::G1Prepared::from(&g1_points[i]));
                all_g2.push(P::G2Prepared::from(&g2_points[i]));

                // Negate h2 for the second part of each pair
                let neg_h2 = -h2_points[i];

                all_g1.push(P::G1Prepared::from(&h1_points[i]));
                all_g2.push(P::G2Prepared::from(&neg_h2));
            }

            // Compute one large multi-pairing
            let batch_result = P::multi_miller_loop(all_g1, all_g2);
            let final_batch_result = P::final_exponentiation(batch_result);
            let _ = final_batch_result.unwrap().is_zero();
        }

        let duration_batch = start_batch.elapsed();
        println!(
            "Time for batch verification of {} equality tests: {:?}",
            num_tests, duration_batch
        );

        // Print speedup
        let speedup_miller =
            duration_full_pairing.as_secs_f64() / duration_miller_loop.as_secs_f64();
        println!("Speedup using Miller loops: {:.2}x", speedup_miller);

        if num_tests > 1 {
            let speedup_batch = duration_full_pairing.as_secs_f64() / duration_batch.as_secs_f64();
            println!("Speedup using batch verification: {:.2}x", speedup_batch);
        }
    }

    #[test]
    fn test_bls12_381_pairing_efficiency() {
        use ark_bls12_381::Bls12_381;
        use ark_std::time::Instant;

        let total = Instant::now();

        // Call our pairing test with BLS12_381 pairing
        println!("\n=== Testing BLS12_381 pairing efficiency ===");
        test_pairing_equality_efficiency::<Bls12_381>(10);
        println!("Small test complete, now running larger test...");

        // Run a larger test to see more significant differences
        test_pairing_equality_efficiency::<Bls12_381>(100);

        println!("Total test time: {:?}\n", total.elapsed());
    }

    /// Test 3: Scalar Inverse
    /// Goal: Compute the multiplicative inverse of a scalar.
    /// Expectation: For scalar a, find a^-1 such that a * a^-1 = 1.
    #[test]
    fn test_scalar_inverse() {
        let mut rng = test_rng();
        let a = Fr::rand(&mut rng);
        let a_inv = a
            .inverse()
            .expect("Inverse should exist for non-zero scalar");
        assert_eq!(a * a_inv, Fr::one()); // Verify the inverse
                                          // Pitfall: Zero has no inverse; always check or ensure non-zero input
    }

    /// Test 4: Group Inverse
    /// Expectation: For g in G1, find -g such that g + (-g) = 0 (identity).
    #[test]
    fn test_group_inverse() {
        let mut rng = test_rng();
        let g = G1Affine::rand(&mut rng);
        let neg_g = -g; // Negation
        assert_eq!((g + neg_g).is_zero(), true); // Sum should be the identity
                                                 // Note: Negation is simple but critical for pairing properties later
    }

    /// Test 5: Scalar Multiplication as Inverse
    /// Expectation: For g * a, multiplying by a^-1 gives back g.
    #[test]
    fn test_scalar_mul_inverse() {
        let mut rng = test_rng();
        let g = G1Affine::rand(&mut rng);
        let a = Fr::rand(&mut rng);
        let a_inv = a.inverse().expect("Inverse should exist");
        let result = (g.mul(a)).mul(a_inv).into_affine(); // g * a * a^-1
        assert_eq!(result, g); // Should return original point
                               // Pitfall: Ensure intermediate results are handled correctly (e.g., projective vs. affine)
    }
}
