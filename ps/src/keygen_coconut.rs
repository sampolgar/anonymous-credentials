use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::{ops::Mul, rand::Rng, vec::Vec, One, Zero};
#[derive(Clone, Debug)]
pub struct PartialSecretKey<E: Pairing> {
    pub index: usize,
    pub x_i: E::ScalarField,
    pub y_i: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct PartialPublicKey<E: Pairing> {
    pub index: usize,
    pub g2_x_i: E::G2Affine,
    pub g2_y_i: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct ThresholdKeys<E: Pairing> {
    pub partial_secret_key: PartialSecretKey<E>,
    pub partial_public_key: PartialPublicKey<E>,
}

#[derive(Clone, Debug)]
pub struct AggregatePublicKey<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub g2_x: E::G2Affine,
    pub g2_y: E::G2Affine,
}
pub fn distributed_keygen<E: Pairing, R: Rng>(
    rng: &mut R,
    n: usize,
    t: usize,
    message_count: usize,
) -> (Vec<ThresholdKeys<E>>, AggregatePublicKey<E>) {
    assert!(t <= n, "Threshold t must be less than or equal to n");

    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    println!("g1: {:?}", g1);
    println!("g2: {:?}", g2);

    // Generate polynomials for x and y
    let x_coeffs: Vec<E::ScalarField> = (0..t).map(|_| E::ScalarField::rand(rng)).collect();
    let y_coeffs: Vec<E::ScalarField> = (0..t).map(|_| E::ScalarField::rand(rng)).collect();
    let x_poly = DensePolynomial::from_coefficients_vec(x_coeffs);
    let y_poly = DensePolynomial::from_coefficients_vec(y_coeffs);

    println!("x polynomial coefficients: {:?}", x_poly.coeffs());
    println!("y polynomial coefficients: {:?}", y_poly.coeffs());

    let mut threshold_keys = Vec::with_capacity(n);
    let mut g2_x_sum = E::G2::zero();
    let mut g2_y_sum = E::G2::zero();

    for i in 1..=n {
        let index = E::ScalarField::from(i as u64);
        let x_i = x_poly.evaluate(&index);
        let y_i = y_poly.evaluate(&index);

        let g2_x_i = g2.mul(x_i).into_affine();
        let g2_y_i = g2.mul(y_i).into_affine();

        g2_x_sum += g2_x_i;
        g2_y_sum += g2_y_i;

        let partial_secret_key = PartialSecretKey { index: i, x_i, y_i };
        let partial_public_key = PartialPublicKey {
            index: i,
            g2_x_i,
            g2_y_i,
        };

        println!("Partial key {}: ", i);
        println!("  x_i: {:?}", x_i);
        println!("  y_i: {:?}", y_i);
        println!("  g2_x_i: {:?}", g2_x_i);
        println!("  g2_y_i: {:?}", g2_y_i);

        threshold_keys.push(ThresholdKeys {
            partial_secret_key,
            partial_public_key,
        });
    }

    let aggregate_public_key = AggregatePublicKey {
        g1,
        g2,
        g2_x: g2_x_sum.into_affine(),
        g2_y: g2_y_sum.into_affine(),
    };

    println!("Aggregate public key:");
    println!("  g2_x: {:?}", aggregate_public_key.g2_x);
    println!("  g2_y: {:?}", aggregate_public_key.g2_y);

    (threshold_keys, aggregate_public_key)
}

// pub fn distributed_keygen<E: Pairing, R: Rng>(
//     rng: &mut R,
//     n: usize,
//     t: usize,
//     message_count: usize,
// ) -> (Vec<ThresholdKeys<E>>, AggregatePublicKey<E>) {
//     assert!(t <= n, "Threshold t must be less than or equal to n");

//     let g1 = E::G1Affine::rand(rng);
//     let g2 = E::G2Affine::rand(rng);

//     // Generate polynomials for x and y
//     let x_coeffs: Vec<E::ScalarField> = (0..t).map(|_| E::ScalarField::rand(rng)).collect();
//     let y_coeffs: Vec<E::ScalarField> = (0..t).map(|_| E::ScalarField::rand(rng)).collect();
//     let x_poly = DensePolynomial::from_coefficients_vec(x_coeffs);
//     let y_poly = DensePolynomial::from_coefficients_vec(y_coeffs);

//     let mut threshold_keys = Vec::with_capacity(n);
//     let mut g2_x_sum = E::G2::zero();
//     let mut g2_y_sum = E::G2::zero();

//     for i in 1..=n {
//         let index = E::ScalarField::from(i as u64);
//         let x_i = x_poly.evaluate(&index);
//         let y_i = y_poly.evaluate(&index);

//         let g2_x_i = g2.mul(x_i).into_affine();
//         let g2_y_i = g2.mul(y_i).into_affine();

//         g2_x_sum += g2_x_i;
//         g2_y_sum += g2_y_i;

//         let partial_secret_key = PartialSecretKey { index: i, x_i, y_i };
//         let partial_public_key = PartialPublicKey {
//             index: i,
//             g2_x_i,
//             g2_y_i,
//         };

//         threshold_keys.push(ThresholdKeys {
//             partial_secret_key,
//             partial_public_key,
//         });
//     }

//     let aggregate_public_key = AggregatePublicKey {
//         g1,
//         g2,
//         g2_x: g2_x_sum.into_affine(),
//         g2_y: g2_y_sum.into_affine(),
//     };

//     (threshold_keys, aggregate_public_key)
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_distributed_keygen() {
        let mut rng = test_rng();
        let n = 5;
        let t = 3;
        let message_count = 2;

        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, message_count);

        assert_eq!(threshold_keys.len(), n);

        // Verify that partial public keys are consistent with partial secret keys
        for keys in &threshold_keys {
            assert_eq!(
                aggregate_pk.g2.mul(keys.partial_secret_key.x_i),
                keys.partial_public_key.g2_x_i.into_group()
            );
            assert_eq!(
                aggregate_pk.g2.mul(keys.partial_secret_key.y_i),
                keys.partial_public_key.g2_y_i.into_group()
            );
        }

        // Verify that the sum of partial public keys equals the aggregate public key
        let mut sum_g2_x = <Bls12_381 as Pairing>::G2::zero();
        let mut sum_g2_y = <Bls12_381 as Pairing>::G2::zero();

        for keys in &threshold_keys {
            sum_g2_x += keys.partial_public_key.g2_x_i.into_group();
            sum_g2_y += keys.partial_public_key.g2_y_i.into_group();
        }

        assert_eq!(sum_g2_x.into_affine(), aggregate_pk.g2_x);
        assert_eq!(sum_g2_y.into_affine(), aggregate_pk.g2_y);
    }
}
