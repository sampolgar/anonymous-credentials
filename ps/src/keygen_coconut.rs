use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{FftField, Field, UniformRand};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};
use ark_std::{ops::Mul, rand::Rng, vec::Vec, Zero};

#[derive(Clone, Debug)]
pub struct PartialSecretKey<F: Field> {
    pub index: usize,
    pub x_i: F,
    pub y_i: F,
}

#[derive(Clone, Debug)]
pub struct PartialPublicKey<E: Pairing> {
    pub index: usize,
    pub g2_x_i: E::G2Affine,
    pub g2_y_i: E::G2Affine,
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
    pub g2_y: E::G2Affine,
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
    message_count: usize,
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

    // Generate polynomials for x and y in evaluation form
    let x_evals = generate_random_evaluations(rng, t, domain);
    let y_evals = generate_random_evaluations(rng, t, domain);

    println!("x polynomial evaluations: {:?}", x_evals.evals);
    println!("y polynomial evaluations: {:?}", y_evals.evals);

    let mut threshold_keys = Vec::with_capacity(n);
    let mut g2_x_sum = E::G2::zero();
    let mut g2_y_sum = E::G2::zero();

    for i in 1..=n {
        let x_i = x_evals.evals[i - 1];
        let y_i = y_evals.evals[i - 1];

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_distributed_keygen() {
        let mut rng = test_rng();
        let domain = GeneralEvaluationDomain::<ark_bls12_381::Fr>::new(5).unwrap();
        let evals = generate_random_evaluations(&mut rng, 3, domain);

        let zero_value = interpolate_at_zero(&evals);
        let random_point = ark_bls12_381::Fr::rand(&mut rng);
        let evaluated_value = evaluate_at(&evals, random_point);
    }
}
