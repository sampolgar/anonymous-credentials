use ark_ec::{
    models::bls12::Bls12Config,
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    CurveGroup,
};
use ark_ff::Field;

pub struct PairingUtils<P: Pairing> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: Pairing> PairingUtils<P>
// where
//     P: Bls12Config,
{
    pub fn copy_point_to_length(point: P::G1Affine, length: &usize) -> Vec<P::G1Affine> {
        vec![point; *length]
    }

    pub fn prepare_g1(g1_points: &[P::G1Affine]) -> Vec<P::G1Prepared> {
        g1_points
            .iter()
            .map(|point| P::G1Prepared::from(*point))
            .collect()
    }

    pub fn prepare_g2(g2_points: &[P::G2Affine]) -> Vec<P::G2Prepared> {
        g2_points
            .iter()
            .map(|point| P::G2Prepared::from(*point))
            .collect()
    }

    pub fn scale_g1(g1_points: &[P::G1Affine], scalars: &[P::ScalarField]) -> Vec<P::G1Affine> {
        g1_points
            .iter()
            .zip(scalars.iter())
            .map(|(point, scalar)| (P::G1::from(*point) * scalar).into_affine())
            .collect()
    }

    pub fn scale_g2(g2_points: &[P::G2Affine], scalars: &[P::ScalarField]) -> Vec<P::G2Affine> {
        g2_points
            .iter()
            .zip(scalars.iter())
            .map(|(point, scalar)| (P::G2::from(*point) * scalar).into_affine())
            .collect()
    }

    pub fn combine_g1_points(
        vec_g1_points: &[P::G1Affine],
        add_g1_points: &[P::G1Affine],
    ) -> Vec<P::G1Affine> {
        let mut combined = vec_g1_points.to_vec();
        combined.extend_from_slice(add_g1_points);
        combined
    }

    pub fn combine_g2_points(
        vec_g2_points: &[P::G2Affine],
        add_g2_points: &[P::G2Affine],
    ) -> Vec<P::G2Affine> {
        let mut combined = vec_g2_points.to_vec();
        combined.extend_from_slice(add_g2_points);
        combined
    }

    pub fn multi_miller_loop(
        g1_prepared: Vec<P::G1Prepared>,
        g2_prepared: Vec<P::G2Prepared>,
    ) -> MillerLoopOutput<P> {
        P::multi_miller_loop(g1_prepared, g2_prepared)
    }

    pub fn final_exponentiation(miller_output: MillerLoopOutput<P>) -> Option<PairingOutput<P>> {
        P::final_exponentiation(miller_output)
    }

    pub fn pairing(
        g1_points: &[P::G1Affine],
        g2_points: &[P::G2Affine],
    ) -> Option<PairingOutput<P>> {
        let g1_prepared = Self::prepare_g1(g1_points);
        let g2_prepared = Self::prepare_g2(g2_points);
        let ml_result = Self::multi_miller_loop(g1_prepared, g2_prepared);
        Self::final_exponentiation(ml_result)
    }
}
