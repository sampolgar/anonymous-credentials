use crate::helpers::*;
use crate::{helpers, keygen, signature};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
};
use schnorr::schnorr::SchnorrProtocol;
use signature::Signature;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

#[derive(Clone, Debug)]
pub struct SchnorrCommitmentPairing<E: Pairing> {
    pub random_blindings: Vec<E::ScalarField>,
    pub t_com: PairingCheck<E>,
}
#[derive(Clone, Debug)]
pub struct SchnorrResponsesPairing<E: Pairing>(pub Vec<E::ScalarField>);

pub struct SchnorrProtocolPairing;

impl SchnorrProtocolPairing {
    // pub fn commit<E: Pairing, R: Rng>(
    //     public_generators_g1: &[E::G1Affine],
    //     public_generators_g2: &[E::G2Affine],
    //     rng: &mut R,
    // ) -> SchnorrCommitmentPairing<E> {
    //     assert_eq!(public_generators_g1.len(), public_generators_g2.len(), "public_generators lengths must match");
    //     // random_blindings [beta, alpha1, alpha2]
    //     // public_generators_g1 = sigma1, sigma1, sigma1
    //     // public_generators g2 = g, y1, y2
    //     let random_blindings: Vec<E::ScalarField> = (0..public_generators_g1.len())
    //         .map(|_| E::ScalarField::rand(rng))
    //         .collect();

    //     let blinded_g1: Vec<E::G1> = public_generators_g1
    //         .iter()
    //         .zip(&random_blindings)
    //         .map(|(base, blinding)| base.mul(*blinding))
    //         .collect();

    //     // Convert blinded G1 elements to affine representation
    //     let blinded_g1_affine: Vec<E::G1Affine> = E::G1::normalize_batch(&blinded_g1);

    //     // Prepare inputs for multi_miller_loop
    //     let g1_prepared: Vec<E::G1Prepared> = blinded_g1_affine
    //         .into_iter()
    //         .map(E::G1Prepared::from)
    //         .collect();
    //     let g2_prepared: Vec<E::G2Prepared> =
    //         public_generators_g2.iter().cloned().map(E::G2Prepared::from).collect();

    //     // Compute the multi-Miller loop
    //     let miller_loop = E::multi_miller_loop(g1_prepared, g2_prepared);

    //     // Perform final exponentiation
    //     let t_com = E::final_exponentiation(miller_loop).unwrap();

    //     SchnorrCommitmentPairing { random_blindings, t_com }
    // }

    pub fn prove<E: Pairing>(
        t_com: &SchnorrCommitmentPairing<E>,
        witnesses: &[E::ScalarField],
        challenge: &E::ScalarField,
    ) -> SchnorrResponsesPairing<E> {
        let schnorr_responsess: Vec<E::ScalarField> = t_com
            .random_blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponsesPairing(schnorr_responsess)
    }
}

// pub fn verify<E: Pairing>(
//     public_generators_g1: &[E::G1Affine],
//     public_generators_g2: &[E::G2Affine],
//     y: &E::TargetField,
//     commitment: &SchnorrCommitmentPairing<E>,
//     schnorr_responses: &Schnorr_responsesPairing<E>,
//     challenge: &E::ScalarField,
// ) -> bool {
//     // lhs = e(base1)^schnorr_responses1 * e(base2)^schnorr_responses2 * ...
//     // rhs = y somehow mul by challenge? - commitment.com_prime
// }
