use crate::commitment::Commitment;
use crate::keygen::{
    gen_keys, gen_keys_improved, SecretKey, SecretKeyImproved, VerificationKey,
    VerificationKeyImproved,
};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One,
};
use utils::pairing::PairingCheck;

#[derive(Clone, Debug)]
pub struct PSUTTSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> PSUTTSignature<E> {
    pub fn sign(
        pp: &PublicParams<E>,
        sk: &SecretKey<E>,
        cmg1: &E::G1Affine,
        rng: &mut impl Rng,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g1.mul(u).into_affine();
        let sigma2 = (cmg1.add(sk.sk)).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn rerandomize(
        &self,
        pp: &PublicParams<E>,
        r_delta: &E::ScalarField,
        u_delta: &E::ScalarField,
    ) -> Self {
        let sigma1_prime = self.sigma1.mul(u_delta);
        let r_times_u = r_delta.mul(u_delta);

        let scalars = vec![r_times_u, *u_delta];
        let points = vec![self.sigma1, self.sigma2];
        let sigma2_prime = E::G1::msm_unchecked(&points, &scalars);

        let proj_points = vec![sigma1_prime, sigma2_prime];
        let affine_points = E::G1::normalize_batch(&proj_points);

        Self {
            sigma1: affine_points[0],
            sigma2: affine_points[1],
        }

        // let sigma1_prime = self.sigma1.mul(u_delta).into_affine();
        // let temp = self.sigma1.mul(r_delta);
        // let sigma2_prime = (temp.add(self.sigma2)).mul(u_delta).into_affine();
        // Self {
        //     sigma1: sigma1_prime,
        //     sigma2: sigma2_prime,
        // }
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        vk: &VerificationKey<E>,
        cmg1: &E::G1Affine,
        cmg2: &E::G2Affine,
    ) -> bool {
        // Verify: e(sigma2, g2) = e(sigma1, vk · cm)
        let p1 = E::pairing(self.sigma2, pp.g2);
        let p2 = E::pairing(self.sigma1, vk.vk.add(cmg2));
        let is_valid = p1 == p2;
        assert_eq!(p1, p2);

        // Verify commitment consistency: e(cmg1, g2) = e(g1, cmg2)
        let p3 = E::pairing(cmg1, pp.g2);
        let p4 = E::pairing(pp.g1, cmg2);
        assert_eq!(p3, p4);

        is_valid
    }

    pub fn verify_with_pairing_checker(
        &self,
        pp: &PublicParams<E>,
        vk: &VerificationKey<E>,
        cmg1: &E::G1Affine,
        cmg2: &E::G2Affine,
    ) -> bool {
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);

        // Optimized check: e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
        let vk_plus_cmg2 = vk.vk.add(cmg2).into_affine();
        let check1 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&self.sigma2, &pp.g2),
                (&self.sigma1.into_group().neg().into_affine(), &vk_plus_cmg2),
            ],
            &E::TargetField::one(),
        );

        // Optimized check: e(cmg1, g2) * e(g1, cmg2)^-1 = 1
        let check2 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&cmg1, &pp.g2),
                (&pp.g1.into_group().neg().into_affine(), &cmg2),
            ],
            &E::TargetField::one(),
        );

        let mut final_check = PairingCheck::<E>::new();
        final_check.merge(&check1);
        final_check.merge(&check2);
        final_check.verify()
    }
}

#[derive(Clone, Debug)]
pub struct PSUTTSignatureImproved<E: Pairing> {
    pub sigma1: E::G2Affine,
    pub sigma2: E::G2Affine,
}

impl<E: Pairing> PSUTTSignatureImproved<E> {
    pub fn sign(
        pp: &PublicParams<E>,
        sk: &SecretKeyImproved<E>,
        cmg2: &E::G2Affine,
        rng: &mut impl Rng,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g2.mul(u).into_affine();
        let sigma2 = (cmg2.add(sk.sk)).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn rerandomize(
        &self,
        pp: &PublicParams<E>,
        r_delta: &E::ScalarField,
        u_delta: &E::ScalarField,
    ) -> Self {
        // For sigma1: simple scalar multiplication
        let sigma1_prime = self.sigma1.mul(u_delta);

        // For sigma2: use multi-scalar multiplication
        // Computing (sigma1 * r_delta + sigma2) * u_delta
        // = sigma1 * (r_delta * u_delta) + sigma2 * u_delta
        let r_times_u = r_delta.mul(u_delta);

        let scalars = vec![r_times_u, *u_delta];
        let points = vec![self.sigma1, self.sigma2];
        let sigma2_prime = E::G2::msm_unchecked(&points, &scalars);

        // Batch conversion to affine
        let proj_points = vec![sigma1_prime, sigma2_prime];
        let affine_points = E::G2::normalize_batch(&proj_points);

        Self {
            sigma1: affine_points[0],
            sigma2: affine_points[1],
        }
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        vk: &VerificationKeyImproved<E>,
        cmg1: &E::G1Affine,
    ) -> bool {
        // Verify: e(g1, sigma2) = e(vk + cmg1, sigma1)
        let p1 = E::pairing(pp.g1, self.sigma2);
        let p2 = E::pairing(vk.vk.add(cmg1), self.sigma1);
        let is_valid = p1 == p2;
        assert_eq!(p1, p2, "pairing verify is wrong psutt improved");
        is_valid
    }

    pub fn verify_with_pairing_checker_improved(
        &self,
        pp: &PublicParams<E>,
        vk: &VerificationKeyImproved<E>,
        cmg1: &E::G1Affine,
    ) -> bool {
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);

        // Optimized check: e(g1, sigma2) * e(vk + cmg1, -sigma1) = 1
        let vk_plus_cmg1 = vk.vk.add(cmg1).into_affine();
        let check = PairingCheck::<E>::rand(
            &mr,
            &[
                (&pp.g1, &self.sigma2),
                (&vk_plus_cmg1, &self.sigma1.into_group().neg().into_affine()),
            ],
            &E::TargetField::one(),
        );

        check.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::Commitment;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_randomized_signature() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let (sk, vk) = gen_keys(&pp, &mut rng);
        let messages = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);

        let sig = PSUTTSignature::sign(&pp, &sk, &commitment.cmg1, &mut rng);
        let is_valid = sig.verify(&pp, &vk, &commitment.cmg1, &commitment.cmg2);
        assert!(is_valid);

        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_sig = sig.rerandomize(&pp, &r_delta, &u_delta);

        let is_randomized_valid = randomized_sig.verify(
            &pp,
            &vk,
            &randomized_commitment.cmg1,
            &randomized_commitment.cmg2,
        );
        assert!(is_randomized_valid, "randomized sig verification failed");
    }

    #[test]
    fn test_randomized_signature_pairing_checker() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let (sk, vk) = gen_keys(&pp, &mut rng);
        let messages = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);

        let sig = PSUTTSignature::sign(&pp, &sk, &commitment.cmg1, &mut rng);
        let is_valid = sig.verify(&pp, &vk, &commitment.cmg1, &commitment.cmg2);
        assert!(is_valid);

        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_sig = sig.rerandomize(&pp, &r_delta, &u_delta);

        let is_randomized_valid = randomized_sig.verify(
            &pp,
            &vk,
            &randomized_commitment.cmg1,
            &randomized_commitment.cmg2,
        );
        assert!(is_randomized_valid, "randomized sig verification failed");
    }

    #[test]
    fn test_randomized_signature_pairing_checker_improved() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let (sk, vk) = gen_keys_improved(&pp, &mut rng);
        let messages = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);

        let sig = PSUTTSignatureImproved::sign(&pp, &sk, &commitment.cmg2, &mut rng);
        let is_valid = sig.verify(&pp, &vk, &commitment.cmg1);
        assert!(is_valid);

        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_sig = sig.rerandomize(&pp, &r_delta, &u_delta);

        let is_randomized_valid = randomized_sig.verify_with_pairing_checker_improved(
            &pp,
            &vk,
            &randomized_commitment.cmg1,
        );
        assert!(is_randomized_valid, "randomized sig verification failed");
    }
}
