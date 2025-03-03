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
}
