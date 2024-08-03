// Inspired by Lovesh's work https://github.com/docknetwork/crypto/blob/main/schnorr_pok/src/lib.rs

//! Schnorr protocol to prove knowledge of 1 or more discrete logs in zero knowledge.
//! Refer [this](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) for more details of Schnorr protocol.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::pairing::{MillerLoopOutput, Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, MulAssign, Neg, Sub},
    rand::Rng,
    vec::Vec,
    UniformRand,
};
use digest::Digest;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use utils::pairing::PairingCheck;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrCommitment<G: AffineRepr> {
    pub random_blindings: Vec<G::ScalarField>,
    pub com_t: G,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrResponses<G: AffineRepr>(pub Vec<G::ScalarField>);

pub struct SchnorrProtocol;

impl SchnorrProtocol {
    // commit takes in public_generators and exponents
    pub fn commit<G: AffineRepr, R: Rng>(
        public_generators: &[G],
        rng: &mut R,
    ) -> SchnorrCommitment<G> {
        // random_blindings hide the exponent like a pedersen commitment e.g. g^m h^r
        let random_blindings: Vec<G::ScalarField> = (0..public_generators.len())
            .map(|_| G::ScalarField::rand(rng))
            .collect();
        // Compute t = public_generators[0] * random_blindings[0] + ... + public_generators[i] * random_blindings[i]
        // multi-scalar multiplication - efficient
        let com_t: G = G::Group::msm_unchecked(public_generators, &random_blindings).into_affine();
        SchnorrCommitment {
            random_blindings,
            com_t,
        }
    }

    pub fn prove<G: AffineRepr>(
        commitment: &SchnorrCommitment<G>,
        witnesses: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> SchnorrResponses<G> {
        // z_i = t_i + e * m_i
        let schnorr_responsess: Vec<G::ScalarField> = commitment
            .random_blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponses(schnorr_responsess)
    }

    // y = g1^m1 * g2^m2 * h^r the public commitment
    pub fn verify<G: AffineRepr>(
        public_generators: &[G],
        y: &G,
        commitment: &SchnorrCommitment<G>,
        schnorr_responses: &SchnorrResponses<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        //e.g.  LHS = g1^(t1 + e*m1) * g2^(t2 + e*m2) * h^(t3 + e*r)
        let lhs = G::Group::msm_unchecked(public_generators, &schnorr_responses.0).into_affine();
        // com^e + com
        let rhs = (commitment.com_t + y.mul(*challenge)).into_affine();
        lhs == rhs
    }

    pub fn compute_random_oracle_challenge<F: PrimeField, D: Digest>(challenge_bytes: &[u8]) -> F {
        let hash_output = D::digest(challenge_bytes);
        F::from_be_bytes_mod_order(&hash_output)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_std::test_rng;
    use blake2::Blake2b512;

    #[test]
    fn test_schnorr_single() {
        let mut rng = test_rng();

        fn check<G: AffineRepr>(rng: &mut impl Rng) {
            let base = G::Group::rand(rng).into_affine();
            let witness = G::ScalarField::rand(rng);
            let public_statement = base.mul(witness).into_affine();
            let blinding = G::ScalarField::rand(rng);

            let commitment = SchnorrProtocol::commit(&[base], rng);
            let mut chal_contrib = Vec::new();
            base.serialize_compressed(&mut chal_contrib).unwrap();
            public_statement
                .serialize_compressed(&mut chal_contrib)
                .unwrap();
            commitment
                .com_t
                .serialize_compressed(&mut chal_contrib)
                .unwrap();

            let challenge = SchnorrProtocol::compute_random_oracle_challenge::<
                G::ScalarField,
                Blake2b512,
            >(&chal_contrib);

            let schnorr_responses = SchnorrProtocol::prove(&commitment, &[witness], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base],
                &public_statement,
                &commitment,
                &schnorr_responses,
                &challenge
            ));
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn test_schnorr_double() {
        let mut rng = test_rng();

        fn check<G: AffineRepr>(rng: &mut impl Rng) {
            let base1 = G::Group::rand(rng).into_affine();
            let witness1 = G::ScalarField::rand(rng);
            let base2 = G::Group::rand(rng).into_affine();
            let witness2 = G::ScalarField::rand(rng);
            let public_statement = (base1.mul(witness1) + base2.mul(witness2)).into_affine();

            let commitment = SchnorrProtocol::commit(&[base1, base2], rng);
            let mut chal_contrib = Vec::new();
            base1.serialize_compressed(&mut chal_contrib).unwrap();
            base2.serialize_compressed(&mut chal_contrib).unwrap();
            public_statement
                .serialize_compressed(&mut chal_contrib)
                .unwrap();

            commitment
                .com_t
                .serialize_compressed(&mut chal_contrib)
                .unwrap();

            let challenge = SchnorrProtocol::compute_random_oracle_challenge::<
                G::ScalarField,
                Blake2b512,
            >(&chal_contrib);
            let schnorr_responses =
                SchnorrProtocol::prove(&commitment, &[witness1, witness2], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base1, base2],
                &public_statement,
                &commitment,
                &schnorr_responses,
                &challenge
            ));
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn test_schnorr_tripple() {
        let mut rng = test_rng();

        // Generate public_generators and witnesses
        let num_witnesses = 3;
        let public_generators: Vec<G1Affine> = (0..num_witnesses)
            .map(|_| G1Affine::rand(&mut rng))
            .collect();
        let witnesses: Vec<Fr> = (0..num_witnesses).map(|_| Fr::rand(&mut rng)).collect();

        // Compute Commitment
        let public_statement =
            G1Projective::msm_unchecked(&public_generators, &witnesses).into_affine();

        // Prover's side
        let commitment = SchnorrProtocol::commit(&public_generators, &mut rng);
        let challenge = Fr::rand(&mut rng); // In practice, this should be derived from a hash
        let schnorr_responses = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        // Verifier's side
        let is_valid = SchnorrProtocol::verify(
            &public_generators,
            &public_statement,
            &commitment,
            &schnorr_responses,
            &challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");
    }
}
