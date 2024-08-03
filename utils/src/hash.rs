use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use blake2::Blake2s256;
use digest::Digest;
use std::marker::PhantomData;

pub struct HashUtil<F: PrimeField, G: AffineRepr<ScalarField = F>> {
    _phantom: PhantomData<(F, G)>,
}

impl<F: PrimeField, G: AffineRepr<ScalarField = F>> HashUtil<F, G> {
    // Hash message to a field element
    pub fn hash_to_field(message: &[u8]) -> F {
        let hash = Blake2s256::digest(message);
        F::from_le_bytes_mod_order(&hash)
    }

    pub fn hash_to_curve(message: &[u8]) -> G {
        let field_element = Self::hash_to_field(message);
        G::generator().mul(field_element).into_affine()
    }

    pub fn hash_fields(elements: &[F]) -> F {
        let mut hasher = Blake2s256::new();
        for e in elements {
            let mut buf = Vec::new();
            e.serialize_uncompressed(&mut buf).unwrap();
            hasher.update(&buf);
        }
        let hash = hasher.finalize();
        F::from_le_bytes_mod_order(&hash)
    }

    pub fn hash_groups_to_field(elements: &[G]) -> F {
        let mut hasher = Blake2s256::new();
        for e in elements {
            let mut buf = Vec::new();
            e.serialize_uncompressed(&mut buf).unwrap();
            hasher.update(&buf);
        }
        let hash = hasher.finalize();
        F::from_le_bytes_mod_order(&hash)
    }
}

// Testing
use ark_bls12_381::{Fr, G1Affine};
pub type BLS12_381HashUtil = HashUtil<Fr, G1Affine>;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{RngCore, SeedableRng};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_hash_to_field() {
        let message = b"Hello, world!";
        let field_element = BLS12_381HashUtil::hash_to_field(message);
        assert_ne!(field_element, Fr::zero());
    }

    #[test]
    fn test_hash_to_curve() {
        let message = b"Hello, world!";
        let curve_point = BLS12_381HashUtil::hash_to_curve(message);
        assert_ne!(curve_point, G1Affine::identity());
    }

    #[test]
    fn test_hash_fields() {
        let mut rng = test_rng();
        let elements: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        let hashed = BLS12_381HashUtil::hash_fields(&elements);
        assert_ne!(hashed, Fr::zero());
    }
}
