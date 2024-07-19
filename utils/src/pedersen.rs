use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use std::ops::{Add, Mul};

pub struct PedersenCommitment<G: AffineRepr> {
    pub g: G,
    pub h: G,
}

impl<G: AffineRepr> PedersenCommitment<G> {
    pub fn new(g: G, h: G) -> Self {
        Self { g, h }
    }

    pub fn commit(&self, m: &G::ScalarField, r: &G::ScalarField) -> G {
        self.g.mul(*m).add(self.h.mul(*r)).into_affine()
    }
}
