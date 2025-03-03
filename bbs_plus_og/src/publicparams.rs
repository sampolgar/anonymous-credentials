use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::vec::Vec;

#[derive(Clone, Debug)]
pub struct PublicParams<E: Pairing> {
    pub L: usize,                  // Maximum number of messages
    pub g0: E::G1Affine,           // Base generator g₀ in G₁
    pub g1: E::G1Affine,           // g1 base for s
    pub g2_to_L: Vec<E::G1Affine>, // G_L for each message
    pub h0: E::G2Affine,           // Base generator h₀ in G₂
}

impl<E: Pairing> PublicParams<E> {
    /// Create new public parameters for BBS+ signatures supporting L messages
    pub fn new(L: &usize, rng: &mut impl Rng) -> Self {
        // Generate random generators
        let g0 = E::G1Affine::rand(rng);
        let g1 = E::G1Affine::rand(rng);
        let h0 = E::G2Affine::rand(rng);

        // Generate L random generators for message binding
        let g2_to_L: Vec<E::G1Affine> = (0..*L).map(|_| E::G1Affine::rand(rng)).collect();

        PublicParams {
            L: *L,
            g0,
            g1,
            g2_to_L,
            h0,
        }
    }

    /// returns [ g0, g1, g2...gL]
    pub fn get_all_bases(&self) -> Vec<E::G1Affine> {
        let mut bases: Vec<E::G1Affine> = Vec::new();
        bases.push(self.g0);
        bases.push(self.g1);
        bases.extend(self.g2_to_L.iter().cloned());
        bases
    }

    /// returns [g1,g2]
    pub fn get_g1_g2(&self) -> (E::G1Affine, E::G1Affine) {
        (self.g1, self.g2_to_L[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_pp_gen() {
        let L = 5; // Support 5 messages
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&L, &mut rng);
    }
}
