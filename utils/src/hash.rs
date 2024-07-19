use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use blake2::Blake2s256;
use digest::Digest;
use lazy_static::lazy_static;
use std::ops::{Add, Mul};

type G1A = G1Affine;

lazy_static! {
    static ref G1: G1A = G1A::generator();
}

pub struct HashUtil;

impl HashUtil {
    // Hash a message to a field element
    pub fn hash_to_field(message: &[u8]) -> Fr {
        let hash = Blake2s256::digest(message);
        Fr::from_le_bytes_mod_order(&hash)
    }

    pub fn hash_to_curve(message: &[u8]) -> G1A {
        let field_element = Self::hash_to_field(message);
        G1.mul(field_element).into_affine()
    }

    pub fn hash_fields(elements: &[Fr]) -> Fr {
        let mut hasher = Blake2s256::new();
        for e in elements {
            let mut buf = Vec::new();
            e.serialize_uncompressed(&mut buf).unwrap();
            hasher.update(&buf);
        }

        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_util() {
        let message = b"Hello World!";
        let field_elem = HashUtil::hash_to_field(message);
        let curve_point = HashUtil::hash_to_curve(message);
        println!("Field elem: {:?}", field_elem);
        println!("Curve point: {:?}", curve_point);

        let multiple_fields = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let hashed_fields = HashUtil::hash_fields(&multiple_fields);
        println!("Hashed fields: {:?}", hashed_fields)
    }
}
