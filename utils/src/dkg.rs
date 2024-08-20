// use ark_ff::Field;
// use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
// use ark_std::rand::RngCore;
// use ark_std::{
//     ops::{Add, Mul, Neg},
//     rand::Rng,
//     sync::Mutex,
//     One, Zero,
// };

// fn multiply_polynomials<F: Field>(
//     p1: &DensePolynomial<F>,
//     p2: &DensePolynomial<F>,
// ) -> DensePolynomial<F> {
//     p1 * p2
// }

// // Function to perform polynomial interpolation
// pub fn interpolate<F: Field>(points: &[(F, F)]) -> DensePolynomial<F> {
//     let degree = points.len() - 1;
//     let mut poly = DensePolynomial::zero();

//     for (i, (x_i, y_i)) in points.iter().enumerate() {
//         let mut term = DensePolynomial::from_coefficients_vec(vec![F::one()]);

//         for (j, (x_j, _)) in points.iter().enumerate() {
//             if i != j {
//                 let denom = *x_i - *x_j;
//                 let factor = DensePolynomial::from_coefficients_vec(vec![-(*x_j), F::one()]);
//                 let mut result = multiply_polynomials(&term, &factor);

//                 term = &term * &(&factor * &denom.inverse().unwrap());

//                 // term.mul_assign(factor * denom.neg());
//             }
//         }

//         poly += &(&term * &y_i);
//     }

//     poly
// }

// // Function to perform polynomial interpolation
// pub fn interpolate2<F: Field>(points: &[(F, F)]) -> DensePolynomial<F> {
//     let mut result = DensePolynomial::zero();

//     for (i, &(x_i, y_i)) in points.iter().enumerate() {
//         let mut numerator = DensePolynomial::from_coefficients_vec(vec![F::one()]);
//         let mut denominator = F::one();

//         for (j, &(x_j, _)) in points.iter().enumerate() {
//             if i != j {
//                 numerator =
//                     &numerator * &DensePolynomial::from_coefficients_vec(vec![-x_j, F::one()]);
//                 denominator *= x_i - x_j;
//             }
//         }

//         let scalar = y_i / denominator;
//         result += &(&numerator * scalar);
//     }

//     result
// }

// // Function to evaluate a polynomial at a given point
// pub fn evaluate_poly<F: Field>(poly: &DensePolynomial<F>, point: F) -> F {
//     poly.evaluate(&point)
// }

// // /// Performs Lagrange interpolation on the given points.
// // pub fn lagrange_interpolate<F: Field>(points: &[(F, F)]) -> Vec<F> {
// //     let n = points.len();
// //     let mut result = vec![F::zero(); n];

// //     for (i, &(x_i, y_i)) in points.iter().enumerate() {
// //         let mut li = F::one();
// //         for (j, &(x_j, _)) in points.iter().enumerate() {
// //             if i != j {
// //                 li *= (F::zero() - x_j) / (x_i - x_j);
// //             }
// //         }
// //         for j in 0..n {
// //             let term = li * y_i;
// //             if j == 0 {
// //                 result[j] += term;
// //             } else {
// //                 let mut coeff = term;
// //                 for (k, &(x_k, _)) in points.iter().enumerate() {
// //                     if k != i {
// //                         coeff *= F::zero() - x_k;
// //                     }
// //                 }
// //                 result[j] += coeff;
// //             }
// //         }
// //     }

// //     result
// // }

// // /// Computes Lagrange coefficients for the given x-coordinates and evaluation point.
// // pub fn lagrange_coefficients<F: Field>(x_values: &[F], x: F) -> Vec<F> {
// //     x_values
// //         .iter()
// //         .map(|&x_i| {
// //             let mut num = F::one();
// //             let mut den = F::one();
// //             for &x_j in x_values.iter() {
// //                 if x_i != x_j {
// //                     num *= x - x_j;
// //                     den *= x_i - x_j;
// //                 }
// //             }
// //             num * den.inverse().unwrap()
// //         })
// //         .collect()
// // }

// /// Checks if the given points lie on a polynomial of degree less than or equal to the expected degree.
// pub fn check_polynomial_degree<F: Field>(
//     x_values: &[F],
//     y_values: &[F],
//     expected_degree: usize,
// ) -> bool {
//     assert_eq!(
//         x_values.len(),
//         y_values.len(),
//         "x and y values must have the same length"
//     );
//     let points: Vec<_> = x_values
//         .iter()
//         .zip(y_values.iter())
//         .map(|(&x, &y)| (x, y))
//         .collect();
//     let interpolated_coeffs = lagrange_interpolate(&points);

//     // The degree is one less than the number of non-zero coefficients
//     let actual_degree = interpolated_coeffs
//         .iter()
//         .rev()
//         .position(|&coeff| coeff != F::zero())
//         .map(|pos| interpolated_coeffs.len() - pos - 1)
//         .unwrap_or(0);

//     if actual_degree > expected_degree {
//         println!(
//             "Interpolated polynomial degree ({}) is higher than expected ({})",
//             actual_degree, expected_degree
//         );
//         return false;
//     }

//     // Verify that the polynomial passes through all points
//     for (&x, &y) in x_values.iter().zip(y_values.iter()) {
//         let calculated_y = evaluate_polynomial(&interpolated_coeffs, x);
//         if calculated_y != y {
//             println!(
//                 "Interpolated polynomial does not pass through point ({:?}, {:?})",
//                 x, y
//             );
//             println!("Calculated y: {:?}", calculated_y);
//             return false;
//         }
//     }

//     true
// }

// /// Evaluates a polynomial at a given point x.
// fn evaluate_polynomial<F: Field>(coeffs: &[F], x: F) -> F {
//     coeffs
//         .iter()
//         .rev()
//         .fold(F::zero(), |acc, &coeff| acc * x + coeff)
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ark_bls12_381::Fr as F;
//     use ark_ff::UniformRand;
//     use ark_std::test_rng;

//     #[test]
//     fn test_lagrange_interpolate3() {
//         let points = vec![
//             (F::from(1u64), F::from(1u64)),
//             (F::from(2u64), F::from(4u64)),
//             (F::from(3u64), F::from(9u64)),
//         ];
//         println!("Input points: {:?}", points);
//         let coeffs = lagrange_interpolate(&points);
//         println!("Interpolated coefficients: {:?}", coeffs);

//         assert_eq!(
//             coeffs.len(),
//             3,
//             "Expected 3 coefficients, got {}",
//             coeffs.len()
//         );
//         assert!(coeffs[2].is_zero(), "Expected constant term to be 0");
//         assert!(coeffs[1].is_zero(), "Expected x term to be 0");
//         assert_eq!(coeffs[0], F::one(), "Expected x^2 term to be 1");

//         // Additional check: evaluate the polynomial at each point
//         for (x, y) in points.iter() {
//             let calculated_y = evaluate_polynomial(&coeffs, *x);
//             println!(
//                 "For x = {:?}: expected y = {:?}, calculated y = {:?}",
//                 x, y, calculated_y
//             );
//             assert_eq!(calculated_y, *y, "Mismatch at x = {:?}", x);
//         }
//     }

//     #[test]
//     fn test_lagrange_interpolate1() {
//         let points = vec![
//             (F::from(1), F::from(1)),
//             (F::from(2), F::from(4)),
//             (F::from(3), F::from(9)),
//         ];
//         let coeffs = lagrange_interpolate(&points);
//         println!("Interpolated coefficients: {:?}", coeffs);

//         assert_eq!(
//             coeffs.len(),
//             3,
//             "Expected 3 coefficients, got {}",
//             coeffs.len()
//         );
//         assert!(
//             coeffs[0].is_zero(),
//             "Expected constant term to be 0, got {:?}",
//             coeffs[0]
//         );
//         assert!(
//             coeffs[1].is_zero(),
//             "Expected x term to be 0, got {:?}",
//             coeffs[1]
//         );
//         assert_eq!(
//             coeffs[2],
//             F::from(1),
//             "Expected x^2 term to be 1, got {:?}",
//             coeffs[2]
//         );

//         // Additional check: evaluate the polynomial at each point
//         for (x, y) in points.iter() {
//             let calculated_y = evaluate_polynomial(&coeffs, *x);
//             println!(
//                 "For x = {:?}: expected y = {:?}, calculated y = {:?}",
//                 x, y, calculated_y
//             );
//             assert_eq!(calculated_y, *y, "Mismatch at x = {:?}", x);
//         }
//     }

//     #[test]
//     fn test_lagrange_interpolate() {
//         let points = vec![
//             (F::from(1), F::from(1)),
//             (F::from(2), F::from(4)),
//             (F::from(3), F::from(9)),
//         ];
//         let coeffs = lagrange_interpolate(&points);
//         assert_eq!(coeffs.len(), 3);
//         assert_eq!(coeffs[0], F::from(0)); // x^2 term
//         assert_eq!(coeffs[1], F::from(0)); // x term
//         assert_eq!(coeffs[2], F::from(1)); // constant term

//         // Additional check: evaluate the polynomial at each point
//         for (x, y) in points.iter() {
//             let calculated_y = evaluate_polynomial(&coeffs, *x);
//             assert_eq!(calculated_y, *y, "Mismatch at x = {:?}", x);
//         }
//     }

//     #[test]
//     fn test_evaluate_polynomial() {
//         let coeffs = vec![F::from(1), F::from(2), F::from(3)]; // 1x^2 + 2x + 3
//         assert_eq!(evaluate_polynomial(&coeffs, F::from(0)), F::from(3));
//         assert_eq!(evaluate_polynomial(&coeffs, F::from(1)), F::from(6));
//         assert_eq!(evaluate_polynomial(&coeffs, F::from(2)), F::from(11));
//     }

//     #[test]
//     fn test_check_polynomial_degree() {
//         let x_values = vec![F::from(1), F::from(2), F::from(3)];
//         let y_values = vec![F::from(1), F::from(4), F::from(9)];
//         assert!(check_polynomial_degree(&x_values, &y_values, 2));
//         assert!(!check_polynomial_degree(&x_values, &y_values, 1));
//     }

//     #[test]
//     fn test_random_polynomial() {
//         let mut rng = test_rng();
//         let degree = 5;
//         let poly: DensePolynomial<F> = DensePolynomial::rand(degree, &mut rng);
//         let x_values: Vec<F> = (0..=degree).map(|i| F::from(i as u64)).collect();
//         let y_values: Vec<F> = x_values.iter().map(|&x| poly.evaluate(&x)).collect();

//         assert!(check_polynomial_degree(&x_values, &y_values, degree));
//         assert!(!check_polynomial_degree(&x_values, &y_values, degree - 1));

//         let interpolated_coeffs = lagrange_interpolate(
//             &x_values
//                 .iter()
//                 .zip(&y_values)
//                 .map(|(&x, &y)| (x, y))
//                 .collect::<Vec<_>>(),
//         );
//         for (original, interpolated) in poly.coeffs.iter().zip(interpolated_coeffs.iter()) {
//             assert_eq!(original, interpolated);
//         }
//     }

//     #[test]
//     fn test_lagrange_interpolate_with_zero_values() {
//         let points = vec![
//             (F::from(0), F::from(1)),
//             (F::from(1), F::from(0)),
//             (F::from(2), F::from(1)),
//         ];
//         let coeffs = lagrange_interpolate(&points);
//         assert_eq!(coeffs.len(), 3);
//         assert!(check_polynomial_degree(
//             &points.iter().map(|&(x, _)| x).collect::<Vec<_>>(),
//             &points.iter().map(|&(_, y)| y).collect::<Vec<_>>(),
//             2
//         ));
//     }
// }
