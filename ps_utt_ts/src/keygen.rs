use crate::dkg_shamir::{generate_shares, reconstruct_secret};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct VerificationKey<E: Pairing> {
    pub vk: E::G1Affine,
}

pub struct ThresholdKeys<E: Pairing> {
    t: usize,
    n: usize,
    x_shares: Vec<(usize, E::ScalarField)>,
    y_shares: Vec<Vec<(usize, E::ScalarField)>>,
}

pub fn gen_keys<E: Pairing>(
    pp: &PublicParams<E>,
    t: usize,
    n: usize,
    rng: &mut impl Rng,
) -> (ThresholdKeys<E>, VerificationKey<E>) {
    let x = E::ScalarField::rand(rng);
    let shares = generate_shares(&x, t, n, rng);
    let vk = pp.g1.mul(x).into_affine();
    (ThresholdKeys { t, n, shares }, VerificationKey { vk })
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_threshold_keygen() {
        let mut rng = test_rng();
        let n = 4; // Total parties
        let t = 3; // Threshold
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);

        // Generate threshold keys
        let (tskeys, vk) = gen_keys(&pp, t, n, &mut rng);

        // Verify the number of shares
        assert_eq!(tskeys.shares.len(), n, "Incorrect number of shares");

        // Reconstruct the secret using t shares
        let shares_subset = &tskeys.shares[0..t];
        let reconstructed_x = reconstruct_secret(shares_subset, t);

        // Compute vk from reconstructed x and compare
        let vk_from_reconstructed = pp.g1.mul(reconstructed_x).into_affine();
        assert_eq!(
            vk_from_reconstructed, vk.vk,
            "Verification key mismatch after reconstruction"
        );
    }
}
