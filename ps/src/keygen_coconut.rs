use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{FftField, Field, PrimeField, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};
use ark_std::{ops::Mul, rand::Rng, vec::Vec, One, Zero};

#[derive(Clone, Debug)]
pub struct PartialSecretKey<F: Field> {
    pub index: usize,
    pub x_i: F,
    pub y_i: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct PartialPublicKey<E: Pairing> {
    pub index: usize,
    pub g2_x_i: E::G2Affine,
    pub g2_y_i: Vec<E::G2Affine>,
}

#[derive(Clone, Debug)]
pub struct ThresholdKeys<E: Pairing> {
    pub partial_secret_key: PartialSecretKey<E::ScalarField>,
    pub partial_public_key: PartialPublicKey<E>,
}

#[derive(Clone, Debug)]
pub struct AggregatePublicKey<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
    pub g2_x: E::G2Affine,
    pub g2_y: Vec<E::G2Affine>,
}

// Helper function to generate random evaluations
fn generate_random_evaluations<F: FftField, R: Rng>(
    rng: &mut R,
    t: usize,
    domain: GeneralEvaluationDomain<F>,
) -> Evaluations<F, GeneralEvaluationDomain<F>> {
    let poly = DensePolynomial::rand(t - 1, rng);
    poly.evaluate_over_domain_by_ref(domain)
}

pub fn interpolate_at_zero<F: FftField>(evals: &Evaluations<F, GeneralEvaluationDomain<F>>) -> F {
    let poly = interpolate_to_poly(evals);
    poly.coeffs()[0]
}

pub fn evaluate_at<F: FftField>(evals: &Evaluations<F, GeneralEvaluationDomain<F>>, point: F) -> F {
    let poly = interpolate_to_poly(evals);
    poly.evaluate(&point)
}

// Helper function to perform interpolation
fn interpolate_to_poly<F: FftField>(
    evals: &Evaluations<F, GeneralEvaluationDomain<F>>,
) -> DensePolynomial<F> {
    let domain = evals.domain();
    let coeffs = domain.ifft(&evals.evals);
    DensePolynomial::from_coefficients_vec(coeffs)
}

pub fn distributed_keygen<E: Pairing, R: Rng>(
    rng: &mut R,
    n: usize,
    t: usize,
    attribute_count: usize,
) -> (Vec<ThresholdKeys<E>>, AggregatePublicKey<E>)
where
    E::ScalarField: FftField,
{
    assert!(t <= n, "Threshold t must be less than or equal to n");

    let g1 = E::G1Affine::rand(rng);
    let g2 = E::G2Affine::rand(rng);

    println!("g1: {:?}", g1);
    println!("g2: {:?}", g2);

    // Create evaluation domain
    let domain = GeneralEvaluationDomain::<E::ScalarField>::new(n)
        .expect("Failed to create evaluation domain");

    // Generate polynomial for x in evaluation form
    let x_evals = generate_random_evaluations(rng, t, domain);

    // Generate polynomials for y_1, ..., y_m in evaluation form
    let y_evals: Vec<Evaluations<_, _>> = (0..attribute_count)
        .map(|_| generate_random_evaluations(rng, t, domain))
        .collect();

    println!("x polynomial evaluations: {:?}", x_evals.evals);
    for (i, y_eval) in y_evals.iter().enumerate() {
        println!("y_{} polynomial evaluations: {:?}", i + 1, y_eval.evals);
    }

    let mut threshold_keys = Vec::with_capacity(n);
    let mut g2_x_sum = E::G2::zero();
    let mut g2_y_sums: Vec<E::G2> = vec![E::G2::zero(); attribute_count];

    for i in 1..=n {
        let x_i = x_evals.evals[i - 1];
        let y_i: Vec<_> = y_evals.iter().map(|y_eval| y_eval.evals[i - 1]).collect();

        let g2_x_i = g2.mul(x_i).into_affine();
        let g2_y_i: Vec<_> = y_i.iter().map(|&y| g2.mul(y).into_affine()).collect();

        g2_x_sum += g2_x_i;
        for j in 0..attribute_count {
            g2_y_sums[j] += g2_y_i[j];
        }

        let partial_secret_key = PartialSecretKey { index: i, x_i, y_i };
        let partial_public_key = PartialPublicKey {
            index: i,
            g2_x_i,
            g2_y_i,
        };

        println!("Partial key {}: ", i);
        println!("  x_i: {:?}", x_i);
        let y_i: Vec<_> = y_evals.iter().map(|y_eval| y_eval.evals[i - 1]).collect();
        let y_i_clone = y_i.clone();

        for (j, &y) in y_i.iter().enumerate() {
            println!("  y_{}_i: {:?}", j + 1, y);
        }

        let g2_y_i: Vec<_> = y_i.iter().map(|&y| g2.mul(y).into_affine()).collect();
        let g2_y_i_clone = g2_y_i.clone(); // Clone g2_y_i to avoid move
        println!("  g2_x_i: {:?}", g2_x_i);
        for (j, &g2_y) in g2_y_i.iter().enumerate() {
            println!("  g2_y_{}_i: {:?}", j + 1, g2_y);
        }

        threshold_keys.push(ThresholdKeys {
            partial_secret_key,
            partial_public_key,
        });
    }

    let aggregate_public_key = AggregatePublicKey {
        g1,
        g2,
        g2_x: g2_x_sum.into_affine(),
        g2_y: g2_y_sums.into_iter().map(|sum| sum.into_affine()).collect(),
    };

    println!("Aggregate public key:");
    println!("  g2_x: {:?}", aggregate_public_key.g2_x);
    for (i, g2_y) in aggregate_public_key.g2_y.iter().enumerate() {
        println!("  g2_y_{}: {:?}", i + 1, g2_y);
    }

    (threshold_keys, aggregate_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_distributed_keygen_multi_attribute() {
        let mut rng = test_rng();
        let n = 5;
        let t = 3;
        let attribute_count = 3;

        let (threshold_keys, aggregate_pk) =
            distributed_keygen::<Bls12_381, _>(&mut rng, n, t, attribute_count);

        assert_eq!(
            threshold_keys.len(),
            n,
            "Incorrect number of threshold keys"
        );
        assert_eq!(
            aggregate_pk.g2_y.len(),
            attribute_count,
            "Incorrect number of g2_y values in aggregate public key"
        );

        for key in &threshold_keys {
            assert_eq!(
                key.partial_secret_key.y_i.len(),
                attribute_count,
                "Incorrect number of y_i values in partial secret key"
            );
            assert_eq!(
                key.partial_public_key.g2_y_i.len(),
                attribute_count,
                "Incorrect number of g2_y_i values in partial public key"
            );
        }
    }
}
