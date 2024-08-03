use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_std::ops::Mul;
pub struct Helpers;

impl Helpers {
    /// Computes a commitment for generic curve groups.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of affine points
    ///
    /// # Returns
    ///
    /// An affine point representing the commitment
    pub fn compute_commitment<
        E: Pairing,
        G: Group<ScalarField = E::ScalarField> + VariableBaseMSM + CurveGroup,
    >(
        additional_scalar: &E::ScalarField,
        additional_point: &G::Affine,
        scalars: &[E::ScalarField],
        points: &[G::Affine],
    ) -> G::Affine {
        assert_eq!(
            scalars.len(),
            points.len(),
            "The number of scalars and points must be equal"
        );

        // Combine all scalars into a single vector, with additional_scalar at the start
        let mut all_scalars = vec![*additional_scalar];
        all_scalars.extend_from_slice(scalars);

        // Combine all points into a single vector, with additional_point at the start
        let mut all_points = vec![*additional_point];
        all_points.extend_from_slice(points);

        // Perform the multi-scalar multiplication
        G::msm_unchecked(&all_points, &all_scalars).into_affine()
    }

    /// Computes a commitment for G1 points.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single G1 point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of G1 affine points
    ///
    /// # Returns
    ///
    /// A G1 affine point representing the commitment
    pub fn compute_commitment_g1<E: Pairing>(
        additional_scalar: &E::ScalarField,
        additional_point: &E::G1Affine,
        scalars: &[E::ScalarField],
        points: &[E::G1Affine],
    ) -> E::G1Affine {
        Self::compute_commitment::<E, E::G1>(additional_scalar, additional_point, scalars, points)
    }

    /// Computes a commitment for G2 points.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single G2 point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of G2 affine points
    ///
    /// # Returns
    ///
    /// A G2 affine point representing the commitment
    pub fn compute_commitment_g2<E: Pairing>(
        additional_scalar: &E::ScalarField,
        additional_point: &E::G2Affine,
        scalars: &[E::ScalarField],
        points: &[E::G2Affine],
    ) -> E::G2Affine {
        Self::compute_commitment::<E, E::G2>(additional_scalar, additional_point, scalars, points)
    }
    /// Computes a vector of scaled points for generic curve groups.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of affine points
    ///
    /// # Returns
    ///
    /// A vector of scaled points in projective coordinates
    pub fn compute_scaled_points<
        E: Pairing,
        G: Group<ScalarField = E::ScalarField> + VariableBaseMSM + CurveGroup,
    >(
        additional_scalar: &E::ScalarField,
        additional_point: &G::Affine,
        scalars: &[E::ScalarField],
        points: &[G::Affine],
    ) -> Vec<G::Affine> {
        assert_eq!(
            scalars.len(),
            points.len(),
            "The number of scalars and points must be equal"
        );

        let mut all_scalars = vec![*additional_scalar];
        all_scalars.extend_from_slice(scalars);

        let mut all_points = vec![*additional_point];
        all_points.extend_from_slice(points);

        let scaled_projective: Vec<G> = all_points
            .into_iter()
            .zip(all_scalars.iter())
            .map(|(point, scalar)| point.mul(*scalar))
            .collect();

        G::normalize_batch(&scaled_projective)
    }

    /// Computes a vector of scaled G1 points.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single G1 point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of G1 affine points
    ///
    /// # Returns
    ///
    /// A vector of scaled G1 points in affine coordinates
    pub fn compute_scaled_points_g1<E: Pairing>(
        additional_scalar: &E::ScalarField,
        additional_point: &E::G1Affine,
        scalars: &[E::ScalarField],
        points: &[E::G1Affine],
    ) -> Vec<E::G1Affine> {
        Self::compute_scaled_points::<E, E::G1>(
            additional_scalar,
            additional_point,
            scalars,
            points,
        )
    }

    /// Computes a vector of scaled G2 points.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `additional_point` - A single G2 point to be added at the start
    /// * `scalars` - A slice of scalar field elements
    /// * `points` - A slice of G2 affine points
    ///
    /// # Returns
    ///
    /// A vector of scaled G2 points in affine coordinates
    pub fn compute_scaled_points_g2<E: Pairing>(
        additional_scalar: &E::ScalarField,
        additional_point: &E::G2Affine,
        scalars: &[E::ScalarField],
        points: &[E::G2Affine],
    ) -> Vec<E::G2Affine> {
        Self::compute_scaled_points::<E, E::G2>(
            additional_scalar,
            additional_point,
            scalars,
            points,
        )
    }

    /// Combines a single scalar with a vector of scalars.
    ///
    /// # Arguments
    ///
    /// * `additional_scalar` - A single scalar to be added at the start
    /// * `scalars` - A slice of scalar field elements
    ///
    /// # Returns
    ///
    /// A vector of scalar field elements with the additional scalar at the start
    pub fn add_scalar_to_vector<E: Pairing>(
        additional_scalar: &E::ScalarField,
        scalars: &[E::ScalarField],
    ) -> Vec<E::ScalarField> {
        let mut all_scalars = vec![*additional_scalar];
        all_scalars.extend_from_slice(scalars);
        all_scalars
    }

    /// Combines a single group element with a vector of group elements.
    ///
    /// # Arguments
    ///
    /// * `additional_element` - A single group element to be added at the start
    /// * `elements` - A slice of group elements
    ///
    /// # Returns
    ///
    /// A vector of group elements with the additional element at the start
    pub fn add_group_element_to_vector<G: Group>(additional_element: &G, elements: &[G]) -> Vec<G> {
        let mut all_elements = vec![*additional_element];
        all_elements.extend_from_slice(elements);
        all_elements
    }

    /// Combines a single affine group element with a vector of affine group elements.
    ///
    /// # Arguments
    ///
    /// * `additional_element` - A single affine group element to be added at the start
    /// * `elements` - A slice of affine group elements
    ///
    /// # Returns
    ///
    /// A vector of affine group elements with the additional element at the start
    pub fn add_affine_to_vector<G: CurveGroup>(
        additional_element: &G::Affine,
        elements: &[G::Affine],
    ) -> Vec<G::Affine> {
        let mut all_elements = vec![*additional_element];
        all_elements.extend_from_slice(elements);
        all_elements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_compute_commitment_g1() {
        let mut rng = thread_rng();
        let scalars: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let points: Vec<G1Affine> = (0..5).map(|_| G1Affine::rand(&mut rng)).collect();
        let additional_scalar = Fr::rand(&mut rng);
        let additional_point = G1Affine::rand(&mut rng);

        let commitment = Helpers::compute_commitment_g1::<Bls12_381>(
            &additional_scalar,
            &additional_point,
            &scalars,
            &points,
        );

        assert!(commitment.is_on_curve());
    }

    #[test]
    fn test_compute_commitment_g2() {
        let mut rng = thread_rng();
        let scalars: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let points: Vec<G2Affine> = (0..5).map(|_| G2Affine::rand(&mut rng)).collect();
        let additional_scalar = Fr::rand(&mut rng);
        let additional_point = G2Affine::rand(&mut rng);

        let commitment = Helpers::compute_commitment_g2::<Bls12_381>(
            &additional_scalar,
            &additional_point,
            &scalars,
            &points,
        );

        assert!(commitment.is_on_curve());
    }

    #[test]
    fn test_compute_scaled_points_g1() {
        let mut rng = thread_rng();
        let scalars: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let points: Vec<G1Affine> = (0..5).map(|_| G1Affine::rand(&mut rng)).collect();
        let additional_scalar = Fr::rand(&mut rng);
        let additional_point = G1Affine::rand(&mut rng);

        let scaled_points = Helpers::compute_scaled_points_g1::<Bls12_381>(
            &additional_scalar,
            &additional_point,
            &scalars,
            &points,
        );

        assert_eq!(scaled_points.len(), 6); // 5 original points + 1 additional point
        for point in scaled_points {
            assert!(point.is_on_curve());
        }
    }

    #[test]
    fn test_compute_scaled_points_g2() {
        let mut rng = thread_rng();
        let scalars: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let points: Vec<G2Affine> = (0..5).map(|_| G2Affine::rand(&mut rng)).collect();
        let additional_scalar = Fr::rand(&mut rng);
        let additional_point = G2Affine::rand(&mut rng);

        let scaled_points = Helpers::compute_scaled_points_g2::<Bls12_381>(
            &additional_scalar,
            &additional_point,
            &scalars,
            &points,
        );

        assert_eq!(scaled_points.len(), 6); // 5 original points + 1 additional point
        for point in scaled_points {
            assert!(point.is_on_curve());
        }
    }

    #[test]
    fn test_add_affine_to_vector() {
        let mut rng = thread_rng();
        let additional_element = G1Affine::rand(&mut rng);
        let elements: Vec<G1Affine> = (0..5).map(|_| G1Affine::rand(&mut rng)).collect();

        let result = Helpers::add_affine_to_vector::<G1Projective>(&additional_element, &elements);

        assert_eq!(result.len(), 6);
        assert_eq!(result[0], additional_element);
        assert_eq!(result[1..], elements[..]);
    }
}
