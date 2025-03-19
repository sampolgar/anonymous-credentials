use crate::error::Error;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::ops::Neg;
use ark_std::rand::Rng;
use ark_std::One;
use schnorr::schnorr_pairing::{
    SchnorrCommitmentPairing, SchnorrProtocolPairing, SchnorrResponsesPairing,
};

/// Zero-knowledge proof that an issuer's keys and commitment keys are well-formed
/// Proves:
/// - sk = g^x and vk = g̃^x (same x)
/// - For each i, g_i = g^y_i and g̃_i = g̃^y_i (same y_i)
#[derive(Clone, Debug)]
pub struct VerKeyProof<E: Pairing> {
    /// Commitment to the randomness used in the proof
    pub schnorr_commitment: SchnorrCommitmentPairing<E>,
    /// Challenge value
    pub challenge: E::ScalarField,
    /// Responses to the challenge
    pub responses: SchnorrResponsesPairing<E>,
}

impl<E: Pairing> VerKeyProof<E> {
    /// Generate a proof that the issuer's keys are well-formed
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `x` - Secret exponent such that sk = g^x and vk = g̃^x
    /// * `y_values` - Exponents such that g_i = g^y_i and g̃_i = g̃^y_i
    /// * `rng` - Random number generator
    pub fn prove(
        pp: &PublicParams<E>,
        x: &E::ScalarField,
        y_values: &[E::ScalarField],
        rng: &mut impl Rng,
    ) -> Self {
        // Verify inputs
        assert_eq!(
            y_values.len(),
            pp.n,
            "Number of y values must match number of commitment key elements"
        );

        // Set up bases in G1 and G2 for the proof
        let mut bases_g1 = vec![pp.g]; // First base is g for sk = g^x
        bases_g1.extend(pp.ck.iter().cloned()); // Add g_i bases for commitment keys

        let mut bases_g2 = vec![pp.g_tilde]; // First base is g_tilde for vk = g_tilde^x
        bases_g2.extend(pp.ck_tilde.iter().cloned()); // Add g_tilde_i bases

        // Set up witnesses - x followed by all y_i values
        let mut witnesses = vec![*x];
        witnesses.extend(y_values.iter().cloned());

        // Generate Schnorr commitment
        let schnorr_commitment = SchnorrProtocolPairing::commit::<E>(&bases_g1, &bases_g2, rng);

        // Generate challenge
        let challenge = E::ScalarField::rand(rng);

        // Generate responses
        let responses = SchnorrProtocolPairing::prove(&schnorr_commitment, &witnesses, &challenge);

        Self {
            schnorr_commitment,
            challenge,
            responses,
        }
    }

    /// Verify a proof that the issuer's keys are well-formed
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `sk` - Secret key (g^x)
    /// * `vk_tilde` - Verification key (g_tilde^x)
    pub fn verify(&self, pp: &PublicParams<E>, sk: &E::G1Affine, vk_tilde: &E::G2Affine) -> bool {
        // Set up bases in G1 and G2 for verification
        let mut bases_g1 = vec![pp.g]; // First base is g for sk = g^x
        bases_g1.extend(pp.ck.iter().cloned()); // Add g_i bases for commitment keys

        let mut bases_g2 = vec![pp.g_tilde]; // First base is g_tilde for vk = g_tilde^x
        bases_g2.extend(pp.ck_tilde.iter().cloned()); // Add g_tilde_i bases

        // Compute the statement for verification
        // The statement is e(g, vk_tilde) * e(sk, g_tilde)^-1 * ∏ e(g_i, g_tilde_i)
        // This should equal 1 if the keys are well-formed

        // Prepare points for pairing
        let mut g1_points = vec![pp.g, *sk];
        g1_points.extend(pp.ck.iter().cloned());

        let mut g2_points = vec![*vk_tilde, pp.g_tilde];
        g2_points.extend(pp.ck_tilde.iter().cloned());

        // Create scalars for the statement (1, -1, 1, ..., 1)
        // This represents e(g, vk_tilde) * e(sk, g_tilde)^-1 * ∏ e(g_i, g_tilde_i)
        let mut statement_scalars = vec![E::ScalarField::one(), E::ScalarField::one().neg()];
        statement_scalars.resize(2 + pp.n, E::ScalarField::one());

        // Compute the statement
        let statement = schnorr::schnorr_pairing::compute_gt_from_g1_g2_scalars(
            &g1_points,
            &g2_points,
            &statement_scalars,
        );

        // Verify the proof against the statement
        SchnorrProtocolPairing::verify::<E>(
            &statement,
            &self.schnorr_commitment.schnorr_commitment,
            &self.challenge,
            &bases_g1,
            &bases_g2,
            &self.responses.0,
        )
    }
}

/// Verification key functionality for the RS signature scheme
pub struct VerKey;

impl VerKey {
    /// Prove that the issuer's keys are well-formed
    pub fn prove<E: Pairing>(
        pp: &PublicParams<E>,
        x: &E::ScalarField,
        y_values: &[E::ScalarField],
        rng: &mut impl Rng,
    ) -> VerKeyProof<E> {
        VerKeyProof::prove(pp, x, y_values, rng)
    }

    /// Verify a proof that the issuer's keys are well-formed
    pub fn verify<E: Pairing>(
        proof: &VerKeyProof<E>,
        pp: &PublicParams<E>,
        sk: &E::G1Affine,
        vk_tilde: &E::G2Affine,
    ) -> bool {
        proof.verify(pp, sk, vk_tilde)
    }
}
