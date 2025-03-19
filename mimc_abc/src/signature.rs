use crate::commitment::Commitment;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::VariableBaseMSM;
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use ark_std::One;
use utils::pairing::PairingCheck;

// Secret and verification keys
pub struct SecretKey<E: Pairing> {
    pub sk: E::G1Affine,
}

impl<E: Pairing> SecretKey<E> {
    pub fn sign(
        &self,
        commitment: &Commitment<E>,
        pp: &PublicParams<E>,
        rng: &mut impl Rng,
    ) -> Signature<E> {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g.mul(u).into_affine();
        let sigma2 = (commitment.cm.add(self.sk)).mul(u).into_affine();
        Signature { sigma1, sigma2 }
    }
}
pub struct VerificationKey<E: Pairing> {
    pub vk_tilde: E::G2Affine,
}

impl<E: Pairing> VerificationKey<E> {
    pub fn verify(
        &self,
        signature: &Signature<E>,
        commitment: &Commitment<E>,
        pp: &PublicParams<E>,
    ) -> bool {
        let left1 = E::pairing(signature.sigma2, pp.g_tilde);
        let right1 = E::pairing(signature.sigma1, self.vk_tilde.add(commitment.cm_tilde));
        assert!(left1 == right1, "Pairing check failed!");

        let left2 = E::pairing(commitment.cm, self.vk_tilde);
        let right2 = E::pairing(pp.g, commitment.cm_tilde);
        assert!(left2 == right2, "Commitment Pairing check fail!");
        true
    }

    pub fn verify_with_pairing_checker(
        &self,
        signature: &Signature<E>,
        commitment: &Commitment<E>,
        pp: &PublicParams<E>,
    ) -> bool {
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);

        // Optimized check: e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
        let vk_plus_cm_tilde = self.vk_tilde.add(commitment.cm_tilde).into_affine();
        let check1 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&signature.sigma2, &pp.g_tilde),
                (
                    &signature.sigma1.into_group().neg().into_affine(),
                    &vk_plus_cm_tilde,
                ),
                (
                    &signature.sigma1.into_group().neg().into_affine(),
                    &vk_plus_cm_tilde,
                ),
            ],
            &E::TargetField::one(),
        );

        // Optimized check: e(cmg1, g2) * e(g1, cmg2)^-1 = 1
        let check2 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&commitment.cm, &pp.g_tilde),
                (&pp.g.into_group().neg().into_affine(), &commitment.cm_tilde),
            ],
            &E::TargetField::one(),
        );

        let mut final_check = PairingCheck::<E>::new();
        final_check.merge(&check1);
        final_check.merge(&check2);
        final_check.verify()
    }
}

// Key generation as a standalone function
pub fn generate_keys<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKey<E>, VerificationKey<E>) {
    let x = E::ScalarField::rand(rng);
    let sk = pp.g.mul(x).into_affine();
    let vk_tilde = pp.g_tilde.mul(x).into_affine();
    (SecretKey { sk }, VerificationKey { vk_tilde })
}

pub struct Signature<E: Pairing> {
    // Signature fields based on your scheme
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    pub fn randomize(&self, r_delta: &E::ScalarField, u_delta: &E::ScalarField) -> Self {
        let sigma1_prime = self.sigma1.mul(u_delta).into_affine();
        let r_times_u = r_delta.mul(u_delta);

        let scalars = vec![r_times_u, *u_delta];
        let points = vec![self.sigma1, self.sigma2];
        let sigma2_prime = E::G1::msm_unchecked(&points, &scalars).into_affine();

        Self {
            sigma1: sigma1_prime,
            sigma2: sigma2_prime,
        }
    }
}
