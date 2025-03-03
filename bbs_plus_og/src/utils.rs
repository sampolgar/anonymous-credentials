use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_std::ops::Mul;

pub struct BBSPlusOgUtils;

impl BBSPlusOgUtils {
    pub fn add_scalar_to_start_of_vector<E: Pairing>(
        scalars: &[E::ScalarField],
        additional_scalar: &E::ScalarField,
    ) -> Vec<E::ScalarField> {
        let mut all_scalars = vec![*additional_scalar];
        all_scalars.extend_from_slice(scalars);
        all_scalars
    }

    /// A vector of scalar field elements with the additional scalar at the end
    pub fn add_scalar_to_end_of_vector<E: Pairing>(
        scalars: &[E::ScalarField],
        additional_scalar: &E::ScalarField,
    ) -> Vec<E::ScalarField> {
        let mut all_scalars = scalars.to_vec();
        all_scalars.push(*additional_scalar);
        all_scalars
    }

    /// takes in [scalars1], [scalars2], returns [scalars1, scalars2]
    pub fn concatenate_scalars<E: Pairing>(
        scalars1: &[E::ScalarField],
        scalars2: &[E::ScalarField],
    ) -> Vec<E::ScalarField> {
        let mut all_scalars = scalars1.to_vec();
        all_scalars.extend_from_slice(scalars2);
        all_scalars
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

    /// Creates a vector of `length` copies of `point`.
    pub fn copy_point_to_length<E: Pairing>(
        point: E::G1Affine,
        length: &usize,
    ) -> Vec<E::G1Affine> {
        vec![point; *length]
    }

    /// Creates a vector of `length` copies of `point`.
    pub fn copy_point_to_length_g2<E: Pairing>(
        point: E::G2Affine,
        length: &usize,
    ) -> Vec<E::G2Affine> {
        vec![point; *length]
    }

    /// takes in g1points, g2points, scalars. Returns a gt point.
    pub fn compute_gt_from_g1_g2_scalars<E: Pairing>(
        g1_points: &[E::G1Affine],
        g2_points: &[E::G2Affine],
        scalars: &[E::ScalarField],
    ) -> PairingOutput<E> {
        assert!(
            g1_points.len() == g2_points.len() && g2_points.len() == scalars.len(),
            "Mismatched number of G1, G2, and scalars"
        );

        // Prepare points for pairing
        // scale each g1 point by a scalar e.g. g1^m1 g2^m2 for [g1,g2] and [m1,m2]
        let scaled_g1_projective: Vec<E::G1> = g1_points
            .iter()
            .zip(scalars.iter())
            .map(|(g1, s)| g1.into_group().mul(s))
            .collect();

        let prepared_g1: Vec<_> = scaled_g1_projective
            .iter()
            .map(E::G1Prepared::from)
            .collect();
        let prepared_g2: Vec<_> = g2_points.iter().map(E::G2Prepared::from).collect();

        // Compute and return the multi-pairing
        E::multi_pairing(prepared_g1, prepared_g2)
    }
}
