use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::AffineRepr;
use ark_ec::Group;
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_std::rand::Rng;
use std::ops::Mul;

#[derive(Clone, Debug)]
pub struct SchnorrCommitmentPairing<E: Pairing> {
    pub blindings: Vec<E::ScalarField>,
    pub schnorr_commitment: PairingOutput<E>,
}

#[derive(Clone, Debug)]
pub struct SchnorrResponsesPairing<E: Pairing>(pub Vec<E::ScalarField>);

pub struct SchnorrProtocolPairing;

impl SchnorrProtocolPairing {
    pub fn commit<E: Pairing>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        rng: &mut impl Rng, //rng: &mut R,
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

        let schnorr_commitment = compute_gt_from_g1_g2_scalars(&bases_g1, &bases_g2, &blindings);

        SchnorrCommitmentPairing {
            blindings,
            schnorr_commitment,
        }
    }

    pub fn commit_with_prepared_blindness<E: Pairing>(
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

        let schnorr_commitment =
            compute_gt_from_g1_g2_scalars(&bases_g1, &bases_g2, &prepared_blindness);

        SchnorrCommitmentPairing {
            blindings: prepared_blindness.to_vec(),
            schnorr_commitment,
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
        let lhs = compute_gt_from_g1_g2_scalars(&bases_g1, &bases_g2, &responses);

        let rhs = statement.mul_bigint(challenge.into_bigint()) + schnorr_commitment;

        lhs == rhs
    }
}

pub fn compute_gt_from_g1_g2_scalars<E: Pairing>(
    g1_points: &[E::G1Affine],
    g2_points: &[E::G2Affine],
    scalars: &[E::ScalarField],
) -> PairingOutput<E> {
    assert!(
        g1_points.len() == g2_points.len() && g2_points.len() == scalars.len(),
        "Mismatched number of G1, G2, and scalars"
    );

    // Prepare points for pairing
    // scale each g1 point by a scalar e.g. g1^m1 g2^m2 for [g1,g2] and [m1,m2]
    let scaled_g1_projective: Vec<E::G1> = g1_points
        .iter()
        .zip(scalars.iter())
        .map(|(g1, s)| g1.into_group().mul(s))
        .collect();

    // E::G1::normalize_batch(&mut scaled_g1_projective);

    let prepared_g1: Vec<_> = scaled_g1_projective
        .iter()
        .map(E::G1Prepared::from)
        .collect();
    let prepared_g2: Vec<_> = g2_points.iter().map(E::G2Prepared::from).collect();

    // Compute and return the multi-pairing
    E::multi_pairing(prepared_g1, prepared_g2)
}

#[cfg(test)]

mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
    use ark_std::test_rng;
    #[test]
    fn test_schnorr_pairing() {
        // Initialize a random number generator for testing
        let mut rng = test_rng();
        let num_bases = 3; // Number of bases to use in the test

        // Step 1: Generate random bases in G1 and G2
        let bases_g1: Vec<G1Affine> = (0..num_bases).map(|_| G1Affine::rand(&mut rng)).collect();
        let bases_g2: Vec<G2Affine> = (0..num_bases).map(|_| G2Affine::rand(&mut rng)).collect();

        // Step 2: Generate random witnesses (scalars)
        let witnesses: Vec<Fr> = (0..num_bases).map(|_| Fr::rand(&mut rng)).collect();

        // Step 3: Compute the statement: ∏ e(g1_i^{w_i}, g2_i)
        let statement = compute_gt_from_g1_g2_scalars(&bases_g1, &bases_g2, &witnesses);

        // Step 4: Create a commitment using random blindings
        let commitment =
            SchnorrProtocolPairing::commit::<Bls12_381>(&bases_g1, &bases_g2, &mut rng);

        // Step 5: Generate a random challenge
        let challenge = Fr::rand(&mut rng);

        // Step 6: Compute the proof (responses)
        let responses = SchnorrProtocolPairing::prove(&commitment, &witnesses, &challenge);

        // Step 7: Verify the proof
        let is_valid = SchnorrProtocolPairing::verify(
            &statement,
            &commitment.schnorr_commitment,
            &challenge,
            &bases_g1,
            &bases_g2,
            &responses.0,
        );

        // Assert that the verification passes
        assert!(is_valid, "Schnorr proof verification failed");
    }
}
