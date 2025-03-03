use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub gamma: E::ScalarField, // Secret key γ
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub w: E::G2Affine, // w = h₀ᵧ in G₂
}

/// Generate a keypair for BBS+ signatures
/// As per the paper: "KenGen. Randomly choose gamma,kl compute w = h*gamma
/// The secret key is γ and the public key is w."
pub fn gen_keys<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKey<E>, PublicKey<E>) {
    // Generate random secret key γ
    let gamma = E::ScalarField::rand(rng);

    // Compute w = h₀ᵧ
    let w = pp.h0.mul(gamma).into_affine();

    (SecretKey { gamma }, PublicKey { w })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::Pairing;

    #[test]
    fn test_keygen() {
        // Initialize test environment
        let mut rng = ark_std::test_rng();
        let L = 5; // Support 5 messages

        // Generate public parameters
        let pp = PublicParams::<Bls12_381>::new(&L, &mut rng);

        // Generate a keypair
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Verify key relationship: w = h₀ᵧ
        let computed_w = pp.h0.mul(sk.gamma).into_affine();
        assert_eq!(pk.w, computed_w, "Public key should be h₀ᵧ");

        // Verify with pairing: e(g₀, w) = e(g₀, h₀ᵧ)
        let pairing1 = Bls12_381::pairing(pp.g0, pk.w);
        let pairing2 = Bls12_381::pairing(pp.g0, pp.h0.mul(sk.gamma).into_affine());
        assert_eq!(pairing1, pairing2, "Pairing consistency check failed");
    }
}
