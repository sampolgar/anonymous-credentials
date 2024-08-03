use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::RngCore;
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
        self.g.mul(*m).add(self.h.mul(r)).into_affine()
    }

    pub fn open(&self, m_prime: &G::ScalarField, r_prime: &G::ScalarField, commitment: &G) -> bool {
        let commitment_prime = self.g.mul(*m_prime).add(self.h.mul(*r_prime)).into_affine();
        &commitment_prime == commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashUtil;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_std::rand::RngCore;

    pub type BLS12_381HashUtil = HashUtil<Fr, G1Affine>;

    #[test]
    fn test_pedersen_commitment() {
        let mut rng = ark_std::test_rng();
        let g = G1Affine::generator();
        let h = G1Affine::rand(&mut rng);

        // Create a new Pedersen commitment instance
        let pedersen_commitment = PedersenCommitment::<G1Affine>::new(g, h);
        // Generate message
        let message = "Hello, world!";
        let message_as_fp = BLS12_381HashUtil::hash_to_field(message.as_bytes());
        let r = Fr::rand(&mut rng);

        // Commit to the message
        let commitment = pedersen_commitment.commit(&message_as_fp, &r);

        // Verify the commitment
        let message_prime = "Hello, world!";
        let message_prime_as_fp = BLS12_381HashUtil::hash_to_field(message_prime.as_bytes());
        assert!(pedersen_commitment.open(&message_prime_as_fp, &r, &commitment));

        // Verify that a different message fails
        let different_message = "Hello Whoops";
        let different_message_as_fp =
            BLS12_381HashUtil::hash_to_field(different_message.as_bytes());
        assert!(!pedersen_commitment.open(&different_message_as_fp, &r, &commitment));
    }

    // #[test]
    // fn test_pedersen_homomorphic_property() {
    //     let mut rng = ark_std::test_rng();

    //     let pedersen = PedersenCommitment::<G1Affine>::new(&mut rng);

    //     let m1 = Fr::rand(&mut rng);
    //     let m2 = Fr::rand(&mut rng);

    //     let (c1, r1) = pedersen.commit(&m1, &mut rng);
    //     let (c2, r2) = pedersen.commit(&m2, &mut rng);

    //     // Compute m1 + m2 and r1 + r2
    //     let m_sum = m1 + m2;
    //     let r_sum = r1 + r2;

    //     // Commit to m_sum
    //     let (c_sum, _) = pedersen.commit(&m_sum, &mut rng);

    //     // Check if c1 + c2 equals c_sum
    //     let c1_plus_c2 = c1.into_group().add(c2.into_group()).into_affine();
    //     assert_eq!(c1_plus_c2, c_sum);

    //     // Verify the summed commitment
    //     assert!(pedersen.verify(&m_sum, &r_sum, &c1_plus_c2));
    // }
}
