use ark_ff::{Field, PrimeField};
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::{test_rng, UniformRand};
use utils::hash::HashUtil;
use utils::pedersen::PedersenCommitment;
use std::ops::{Add, Mul};

pub struct PedersenProof<G: AffineRepr> {
    pub com: G,
    pub com_prime: G,
    pub z1: G::ScalarField,
    pub z2: G::ScalarField,
}

pub struct PedersenSigmaProtocol<G: AffineRepr> {
    commitment: PedersenCommitment<G>,
}

impl<G: AffineRepr> PedersenSigmaProtocol<G> {
    pub fn new(commitment: PedersenCommitment<G>) -> Self {
        Self { commitment }
    }

    pub fn prove(&self, m: &G::ScalarField, r: &G::ScalarField) -> PedersenProof<G> {
        let com = self.commitment.commit(m, r);
        let m_prime = G::ScalarField::rand(&mut test_rng());
        let r_prime = G::ScalarField::rand(&mut test_rng());
        let com_prime = self.commitment.commit(&m_prime, &r_prime);
        let e = self.compute_challenge(&com, &com_prime);
    }

    fn compute_challenge(&self, com: &G, com_prime: &G) -> G::ScalarField {
        let mut to_hash = Vec::new();
        com.serialize_uncompressed(&mut to_hash).unwrap();
        com_prime.serialize_uncompressed(&mut to_hash).unwrap();
        self.c.g.serialize_uncompressed(&mut to_hash).unwrap();
        to_hash.extend_from_slice(b"proof of knowledge of com opening");
        G::ScalarField::from_le_bytes_mod_order(&blake2::Blake2s256::digest(&to_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_proof(){
        let g = G1Affine::generator();
        let h = g.mul(Fr::from(2u32)).into_affine();
        let commitment = PedersenCommitment::new(g,h)
    }
}
