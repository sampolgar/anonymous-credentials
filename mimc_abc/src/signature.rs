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
use utils::pairing::{create_check, PairingCheck};

// Secret and verification keys
pub struct SecretKey<E: Pairing> {
    pub sk: E::G1Affine,
    x: E::ScalarField,
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
    pub fn get_x(&self) -> E::ScalarField {
        self.x
    }

    pub fn new(sk: E::G1Affine, x: E::ScalarField) -> Self {
        Self { sk, x }
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

        let left2 = E::pairing(commitment.cm, pp.g_tilde);
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
        // Calculate vk + commitment in G2
        let vk_plus_cm_tilde = self.vk_tilde.add(commitment.cm_tilde).into_affine();

        // Create signature verification check: e(sigma2, g_tilde) * e(-sigma1, vk+cm_tilde) = 1
        let sig_check = create_check::<E>(
            &[
                (&signature.sigma2, &pp.g_tilde),
                (
                    &signature.sigma1.into_group().neg().into_affine(),
                    &vk_plus_cm_tilde,
                ),
            ],
            None, // defaults to 1
        );

        // Create commitment consistency check: e(cm, g_tilde) * e(-g, cm_tilde) = 1
        let cm_check = create_check::<E>(
            &[
                (&commitment.cm, &pp.g_tilde),
                (&pp.g.into_group().neg().into_affine(), &commitment.cm_tilde),
            ],
            None,
        );

        // Merge checks and verify
        let mut final_check = PairingCheck::<E>::new();
        final_check.merge(&sig_check);
        final_check.merge(&cm_check);
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
    (SecretKey { sk, x }, VerificationKey { vk_tilde })
}
#[derive(Clone)]
pub struct Signature<E: Pairing> {
    // Signature fields based on your scheme
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> Signature<E> {
    pub fn randomize(&self, delta_r: &E::ScalarField, delta_u: &E::ScalarField) -> Self {
        let sigma1_prime = self.sigma1.mul(delta_u).into_affine();
        let r_times_u = delta_r.mul(delta_u);

        let scalars = vec![r_times_u, *delta_u];
        let points = vec![self.sigma1, self.sigma2];
        let sigma2_prime = E::G1::msm_unchecked(&points, &scalars).into_affine();

        Self {
            sigma1: sigma1_prime,
            sigma2: sigma2_prime,
        }
    }
}
