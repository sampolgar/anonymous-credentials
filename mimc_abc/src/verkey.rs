use crate::error::Error;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use rayon::iter::Map;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

/// Zero-knowledge proof that an issuer's keys and commitment keys are well-formed
/// Proves:
/// - sk = g^x and vk = g̃^x (same x)
/// - For each i, g_i = g^y_i and g̃_i = g̃^y_i (same y_i)
#[derive(Clone, Debug)]
pub struct VerKeyProof<E: Pairing> {
    pub x_schnorr_com_g: E::G1Affine,
    pub x_schnorr_com_g_tilde: E::G2Affine,
    pub x_response: E::ScalarField,
    pub t1: Vec<E::G1Affine>,
    pub t2: Vec<E::G2Affine>,
    pub responses: Vec<E::ScalarField>,
    pub challenge: E::ScalarField,
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

        // Generate challenge
        let challenge = E::ScalarField::rand(rng);

        // first prove g^x and g_tilde^x by generating schnorr commitments in g, g_tilde
        // then we use vk to prove schnorr in g_tilde, then use pairing e(g, x_schnorr_com_g_tilde) = e(g_tilde, x_schnorr_com_g)
        let x_blinding = E::ScalarField::rand(rng);
        let x_schnorr_com_g = pp.g.mul(x_blinding).into_affine();
        let x_schnorr_com_g_tilde = pp.g_tilde.mul(x_blinding).into_affine();
        let x_response = x_blinding + challenge * x;

        // now we prove ck = ck_tilde
        // we do schnorr for each base in G1, then use the same randomness in G2
        // generate randomness
        let blindings = (0..y_values.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();

        // Compute T1_i = g^{r_i} for each i
        let t1: Vec<E::G1Affine> = blindings
            .iter()
            .map(|&r| pp.g.mul(r).into_affine())
            .collect();

        // Compute T2_i = g_tilde^{r_i} for each i
        let t2: Vec<E::G2Affine> = blindings
            .iter()
            .map(|&r| pp.g_tilde.mul(r).into_affine())
            .collect();

        // Compute responses s_i = r_i + c * y_i
        let responses: Vec<E::ScalarField> = blindings
            .iter()
            .zip(y_values.iter())
            .map(|(&r, &y)| r + challenge * y)
            .collect();
        // Generate responses
        // let responses = SchnorrProtocol::prove(&schnorr_commitment_g1, &y_values, &challenge);

        Self {
            x_schnorr_com_g,
            x_schnorr_com_g_tilde,
            x_response,
            t1,
            t2,
            responses,
            challenge,
        }
    }

    /// Verify a proof that the issuer's keys are well-formed
    ///
    /// # Arguments
    /// * `pp` - Public parameters
    /// * `vk_tilde` - Verification key (g_tilde^x)
    pub fn verify(&self, pp: &PublicParams<E>, vk_tilde: &E::G2Affine) -> bool {
        assert_eq!(
            vk_tilde.mul(self.challenge) + self.x_schnorr_com_g_tilde,
            pp.g_tilde.mul(self.x_response),
            "Verification key x is not well-formed, or the proof isn't working"
        );

        let lhs = E::pairing(pp.g, self.x_schnorr_com_g_tilde);
        let rhs = E::pairing(self.x_schnorr_com_g, pp.g_tilde);
        if lhs != rhs {
            println!("false!!!");
            return false;
        }

        // Check vector lengths
        if self.t1.len() != pp.n || self.t2.len() != pp.n || self.responses.len() != pp.n {
            return false;
        }

        // Verify ck and ck_tilde for each i
        for i in 0..pp.n {
            let t1_i = self.t1[i];
            let t2_i = self.t2[i];
            let s_i = self.responses[i];
            let ck_tilde_i = pp.ck_tilde[i];

            // Check g_tilde^{s_i} == t2_i * ck_tilde[i]^c
            let lhs = pp.g_tilde.mul(s_i).into_affine();
            let rhs = (t2_i.into_group() + ck_tilde_i.mul(self.challenge)).into_affine();
            if lhs != rhs {
                return false;
            }

            // Check e(t1_i, g_tilde) == e(g, t2_i)
            let pairing_lhs = E::pairing(t1_i, pp.g_tilde);
            let pairing_rhs = E::pairing(pp.g, t2_i);
            if pairing_lhs != pairing_rhs {
                return false;
            }
        }

        true
    }
}

// pub fn combine_commitment_key<G: AffineRepr>(ck: &[G]) -> G {
//     // Start with the identity element (zero point)
//     let mut combined_point = G::Group::zero();

//     // Add each point in the commitment key
//     for point in ck {
//         combined_point += point.into_group();
//     }

//     // Convert back to affine representation
//     combined_point.into_affine()
// }

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
        vk_tilde: &E::G2Affine,
    ) -> bool {
        proof.verify(pp, vk_tilde)
    }
}
