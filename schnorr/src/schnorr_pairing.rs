use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ec::Group;
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;
use std::ops::Mul;
use utils::helpers::Helpers;
use utils::pairing::{create_check, verify_pairing_equation, PairingCheck};

#[derive(Clone, Debug)]
pub struct SchnorrCommitmentPairing<E: Pairing> {
    pub blindings: Vec<E::ScalarField>,
    pub commited_blindings_gt: PairingOutput<E>,
}

#[derive(Clone, Debug)]
pub struct SchnorrCommitmentPairingCheck<E: Pairing> {
    pub blindings: Vec<E::ScalarField>,
    pub committed_blindings_check: PairingCheck<E>,
}

#[derive(Clone, Debug)]
pub struct SchnorrResponsesPairing<E: Pairing>(pub Vec<E::ScalarField>);

pub struct SchnorrProtocolPairing;

impl SchnorrProtocolPairing {
    pub fn commit<E: Pairing, R: Rng>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        rng: &mut R,
    ) -> SchnorrCommitmentPairing<E> {
        assert_eq!(
            bases_g1.len(),
            bases_g2.len(),
            "public_generators lengths must match"
        );

        // random_blindings hide the exponent like a pedersen commitment e.g. g^m h^r
        let blindings: Vec<E::ScalarField> = (0..bases_g1.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();
        // scale one side of the pairing eqn by blinding. e(blinding * sigma1, y1)..
        let scaled_g1bases_by_blindings =
            Helpers::compute_scaled_points_g1::<E>(None, None, &blindings, &bases_g1);

        let commited_blindings_gt =
            Helpers::compute_gt::<E>(&scaled_g1bases_by_blindings, &bases_g2);

        SchnorrCommitmentPairing {
            blindings,
            commited_blindings_gt,
        }
    }

    pub fn commit_pairing_checker<E: Pairing, R: Rng>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        rng: &mut R,
    ) -> SchnorrCommitmentPairingCheck<E> {
        assert_eq!(
            bases_g1.len(),
            bases_g2.len(),
            "public_generators lengths must match"
        );

        // random_blindings hide the exponent like a pedersen commitment e.g. g^m h^r
        let blindings: Vec<E::ScalarField> = (0..bases_g1.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        let scaled_sigma1_vec: Vec<E::G1Affine> = blindings
            .iter()
            .map(|exp| bases_g1[0].mul(*exp).into_affine())
            .collect();

        let pairs: Vec<(&E::G1Affine, &E::G2Affine)> = scaled_sigma1_vec
            .iter()
            .enumerate()
            .map(|(i, scaled)| (scaled, &bases_g2[i]))
            .collect();

        let committed_blindings_check = create_check(&pairs, None);

        SchnorrCommitmentPairingCheck {
            blindings,
            committed_blindings_check,
        }
    }

    pub fn commit_with_prepared_blindness<E: Pairing, R: Rng>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        prepared_blindness: &[E::ScalarField], //[0,0,blinding,0,0,0,blinding]...
        rng: &mut R,
    ) -> SchnorrCommitmentPairing<E> {
        assert!(
            bases_g1.len() == bases_g2.len() && bases_g1.len() == prepared_blindness.len(),
            "lengths of bases {}, {} and prepared blindness {} must match",
            bases_g1.len(),
            bases_g2.len(),
            prepared_blindness.len()
        );

        // generate blinding factors for t and m1, m2,...
        let mut blindings = vec![];
        for blinding in prepared_blindness.iter() {
            if blinding.is_zero() {
                blindings.push(E::ScalarField::rand(rng));
            } else {
                blindings.push(*blinding);
            }
        }

        // scale one side of the pairing eqn by blinding. e(blinding * sigma1, y1)..
        let scaled_g1bases_by_blindings =
            Helpers::compute_scaled_points_g1::<E>(None, None, &blindings, &bases_g1);

        let commited_blindings_gt =
            Helpers::compute_gt::<E>(&scaled_g1bases_by_blindings, &bases_g2);

        SchnorrCommitmentPairing {
            blindings,
            commited_blindings_gt,
        }
    }

    // takes in bases in g1, g2, and prepared blindness
    pub fn commit_with_prepared_blindness2<E: Pairing>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        prepared_blindness: &[E::ScalarField],
    ) -> SchnorrCommitmentPairing<E> {
        assert!(
            bases_g1.len() == bases_g2.len() && bases_g1.len() == prepared_blindness.len(),
            "lengths of bases {}, {} and prepared blindness {} must match",
            bases_g1.len(),
            bases_g2.len(),
            prepared_blindness.len()
        );

        // scale one side of the pairing eqn by blinding. e(blinding * sigma1, y1)..
        let scaled_g1bases_by_blindings =
            Helpers::compute_scaled_points_g1::<E>(None, None, &prepared_blindness, &bases_g1);

        let commited_blindings_gt =
            Helpers::compute_gt::<E>(&scaled_g1bases_by_blindings, &bases_g2);

        SchnorrCommitmentPairing {
            blindings: prepared_blindness.to_vec(),
            commited_blindings_gt,
        }
    }

    pub fn prove<E: Pairing>(
        schnorr_commitment: &SchnorrCommitmentPairing<E>,
        witnesses: &[E::ScalarField],
        challenge: &E::ScalarField,
    ) -> SchnorrResponsesPairing<E> {
        let schnorr_responses: Vec<E::ScalarField> = schnorr_commitment
            .blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponsesPairing(schnorr_responses)
    }

    pub fn verify<E: Pairing>(
        statement: &PairingOutput<E>,
        schnorr_commitment: &PairingOutput<E>,
        challenge: &E::ScalarField,
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        responses: &[E::ScalarField],
    ) -> bool {
        assert!(
            bases_g1.len() == bases_g2.len() && bases_g1.len() == responses.len(),
            "bases in g1, g2, and scalars in responses must match length, found {}, {}, {}",
            bases_g1.len(),
            bases_g2.len(),
            responses.len()
        );

        let scaled_g1_by_responses =
            Helpers::compute_scaled_points_g1::<E>(None, None, responses, bases_g1);

        let lhs = Helpers::compute_gt::<E>(&scaled_g1_by_responses, bases_g2);

        let rhs = statement.mul_bigint(challenge.into_bigint()) + schnorr_commitment;

        lhs == rhs
    }
}
