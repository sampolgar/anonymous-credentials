use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_std::ops::Mul;

pub struct PSUtils;
impl PSUtils {
    /// Creates a vector of `length` copies of `point`.
    pub fn copy_point_to_length<E: Pairing>(
        point: E::G1Affine,
        length: &usize,
    ) -> Vec<E::G1Affine> {
        vec![point; *length]
    }

    /// Computes ∏ e(g1_i, g2_i) from G1 and G2 points.
    ///
    /// # Panics
    ///
    /// Panics if lengths of `g1_points` and `g2_points` mismatch.
    pub fn compute_gt<E: Pairing>(
        g1_points: &[E::G1Affine],
        g2_points: &[E::G2Affine],
    ) -> PairingOutput<E> {
        assert_eq!(
            g1_points.len(),
            g2_points.len(),
            "Mismatched number of G1 and G2 points"
        );

        // Prepare points for pairing
        let prepared_g1: Vec<_> = g1_points.iter().map(E::G1Prepared::from).collect();
        let prepared_g2: Vec<_> = g2_points.iter().map(E::G2Prepared::from).collect();

        // Compute and return the multi-pairing
        E::multi_pairing(prepared_g1, prepared_g2)
    }

    /// Computes ∏ e(g1_i^{scalar_i}, g2_i) from G1 points, G2 points, and scalars.
    ///
    /// # Panics
    ///
    /// Panics if lengths of `g1_points`, `g2_points`, and `scalars` mismatch.
    pub fn compute_gt_from_g1_g2_scalars<E: Pairing>(
        g1_points: &[E::G1Affine],
        g2_points: &[E::G2Affine],
        scalars: &[E::ScalarField],
    ) -> PairingOutput<E> {
        assert!(
            g1_points.len() == g2_points.len() && g2_points.len() == scalars.len(),
            "Mismatched number of G1, G2, and scalars"
        );

        // Scale each G1 point by its corresponding scalar, resulting in projective points
        let scaled_g1_projective: Vec<E::G1> = g1_points
            .iter()
            .zip(scalars.iter())
            .map(|(g1, s)| g1.into_group().mul(s))
            .collect();

        // Normalize the projective points into affine points
        let scaled_g1_affine: Vec<E::G1Affine> = E::G1::normalize_batch(&scaled_g1_projective);

        // Prepare points for pairing
        let prepared_g1: Vec<E::G1Prepared> = scaled_g1_affine
            .iter()
            .map(|p| E::G1Prepared::from(*p))
            .collect();
        let prepared_g2: Vec<E::G2Prepared> =
            g2_points.iter().map(|p| E::G2Prepared::from(*p)).collect();

        // Compute and return the multi-pairing
        E::multi_pairing(prepared_g1, prepared_g2)
    }

    pub fn add_scalar_to_end_of_vector<E: Pairing>(
        scalars: &[E::ScalarField],
        additional_scalar: &E::ScalarField,
    ) -> Vec<E::ScalarField> {
        let mut all_scalars = scalars.to_vec();
        all_scalars.push(*additional_scalar);
        all_scalars
    }
}
