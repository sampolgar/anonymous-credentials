// Inspired by Lovesh's work https://github.com/docknetwork/crypto/blob/main/schnorr_pok/src/lib.rs

//! Schnorr protocol to prove knowledge of 1 or more discrete logs in zero knowledge.
//! Refer [this](https://crypto.stanford.edu/cs355/19sp/lec5.pdf) for more details of Schnorr protocol.
//!
//! Also implements the proof of knowledge of discrete log in pairing groups, i.e. given prover and verifier
//! both know (`A1`, `Y1`), and prover additionally knows `B1`, prove that `e(A1, B1) = Y1`. Similarly,
//! proving `e(A2, B2) = Y2` when only prover knows `A2` but both know (`B2`, `Y2`). See [`discrete_log_pairing`].
//!
//! Also implements the proof of **inequality of discrete log** (a value committed in a Pedersen commitment),
//! either with a public value or with another discrete log in [`Inequality`]. eg. Given a message `m`,
//! its commitment `C = g * m + h * r` and a public value `v`, proving that `m` ≠ `v`. Or given 2 messages
//! `m1` and `m2` and their commitments `C1 = g * m1 + h * r1` and `C2 = g * m2 + h * r2`, proving `m1` ≠ `m2`
//!
//! Also implements the proof of **inequality of discrete log** when only one of the discrete log is known to
//! the prover. i.e. given `y = g * x` and `z = h * k`, prover and verifier know `g`, `h`, `y` and `z` and
//! prover additionally knows `x` but not `k`.
//!
//! Also impelements partial Schnorr proof where response for some witnesses is not generated. This is useful
//! when several Schnorr protocols are executed together and they share some witnesses. The response for those
//! witnesses will be generated in one Schnorr proof while the other protocols will generate partial Schnorr
//! proofs where responses for those witnesses will be missing.  
//!
//! We outline the steps of Schnorr protocol.
//! Prover wants to prove knowledge of `x` in `y = g * x` (`y` and `g` are public knowledge)
//! **Step 1**: Prover generates randomness `r`, and sends `t = g * r` to Verifier.
//! **Step 2**: Verifier generates random challenge `c` and send to Prover.
//! **Step 3**: Prover produces `s = r + x*c`, and sends s to Verifier.
//! **Step 4**: Verifier checks that `g * s = (y * c) + t`.
//!
//! For proving knowledge of multiple messages like `x_1` and `x_2` in `y = g_1*x_1 + g_2*x_2`:
//! **Step 1**: Prover generates randomness `r_1` and `r_2`, and sends `t = g_1*r_1 + g_2*r_2` to Verifier
//! **Step 2**: Verifier generates random challenge `c` and send to Prover
//! **Step 3**: Prover produces `s_1 = r_1 + x_1*c` and `s_2 = r_2 + x_2*c`, and sends `s_1` and `s_2` to Verifier
//! **Step 4**: Verifier checks that `g_1*s_1 + g_2*s_2 = y*c + t`
//!
//! Above can be generalized to more than 2 `x`s

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
use blake2::Blake2b512;
use digest::Digest;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrCommitment<G: AffineRepr> {
    pub blindings: Vec<G::ScalarField>,
    pub ti: G,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrResponse<G: AffineRepr>(pub Vec<G::ScalarField>);

pub struct SchnorrProtocol;

impl SchnorrProtocol {
    // commit takes in bases and exponents
    pub fn commit<G: AffineRepr, R: Rng>(bases: &[G], rng: &mut R) -> SchnorrCommitment<G> {
        // blindings hide the exponent like a pedersen commitment e.g. g^m h^r
        let blindings: Vec<G::ScalarField> = (0..bases.len())
            .map(|_| G::ScalarField::rand(rng))
            .collect();

        // Compute t = bases[0] * blindings[0] + ... + bases[i] * blindings[i]
        // multi-scalar multiplication - efficient
        let ti: G = G::Group::msm_unchecked(bases, &blindings).into_affine();
        SchnorrCommitment { blindings, ti }
    }

    pub fn prove<G: AffineRepr>(
        commitment: &SchnorrCommitment<G>,
        witnesses: &[G::ScalarField],
        challenge: &G::ScalarField,
    ) -> SchnorrResponse<G> {
        // z_i = t_i + e * m_i
        let responses: Vec<G::ScalarField> = commitment
            .blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponse(responses)
    }

    // y = g1^m1 * g2^m2 * h^r the public commitment
    pub fn verify<G: AffineRepr>(
        bases: &[G],
        y: &G,
        commitment: &SchnorrCommitment<G>,
        response: &SchnorrResponse<G>,
        challenge: &G::ScalarField,
    ) -> bool {
        //e.g.  LHS = g1^(t1 + e*m1) * g2^(t2 + e*m2) * h^(t3 + e*r)
        let lhs = G::Group::msm_unchecked(bases, &response.0).into_affine();
        // com^e + com
        let rhs = (commitment.ti + y.mul(*challenge)).into_affine();
        lhs == rhs
    }

    pub fn compute_random_oracle_challenge<F: PrimeField, D: Digest>(challenge_bytes: &[u8]) -> F {
        let mut hash_output = D::digest(challenge_bytes);
        F::from_be_bytes_mod_order(&hash_output)
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrCommitmentPairing<E: Pairing> {
    pub blindings: Vec<E::ScalarField>,
    pub t_com: PairingOutput<E>,
}
#[derive(Clone, Debug)]
pub struct SchnorrResponsePairing<E: Pairing>(pub Vec<E::ScalarField>);

pub struct SchnorrProtocolPairing;

impl SchnorrProtocolPairing {
    pub fn prepare<E: Pairing>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        messages: &[E::ScalarField],
    ) -> E::PairingOutput {
        let messages_g1: Vec<E::G1> = bases_g1
            .iter()
            .zip(messages)
            .map(|(base, message)| base.mul(*message))
            .collect();

        let message_g1_affine: Vec<E::G1Affine> = E::G1::normalize_batch(&messages_g1);
    }
    pub fn commit<E: Pairing, R: Rng>(
        bases_g1: &[E::G1Affine],
        bases_g2: &[E::G2Affine],
        rng: &mut R,
    ) -> SchnorrCommitmentPairing<E> {
        assert_eq!(bases_g1.len(), bases_g2.len(), "Bases lengths must match");
        // blindings [beta, alpha1, alpha2]
        // bases_g1 = sigma1, sigma1, sigma1
        // bases g2 = g, y1, y2
        let blindings: Vec<E::ScalarField> = (0..bases_g1.len())
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        let blinded_g1: Vec<E::G1> = bases_g1
            .iter()
            .zip(&blindings)
            .map(|(base, blinding)| base.mul(*blinding))
            .collect();

        // Convert blinded G1 elements to affine representation
        let blinded_g1_affine: Vec<E::G1Affine> = E::G1::normalize_batch(&blinded_g1);

        // Prepare inputs for multi_miller_loop
        let g1_prepared: Vec<E::G1Prepared> = blinded_g1_affine
            .into_iter()
            .map(E::G1Prepared::from)
            .collect();
        let g2_prepared: Vec<E::G2Prepared> =
            bases_g2.iter().cloned().map(E::G2Prepared::from).collect();

        // Compute the multi-Miller loop
        let miller_loop = E::multi_miller_loop(g1_prepared, g2_prepared);

        // Perform final exponentiation
        let t_com = E::final_exponentiation(miller_loop).unwrap();

        SchnorrCommitmentPairing { blindings, t_com }
    }

    pub fn prove<E: Pairing>(
        t_com: &SchnorrCommitmentPairing<E>,
        witnesses: &[E::ScalarField],
        challenge: &E::ScalarField,
    ) -> SchnorrResponsePairing<E> {
        let responses: Vec<E::ScalarField> = t_com
            .blindings
            .iter()
            .zip(witnesses.iter())
            .map(|(b, w)| *b + (*w * challenge))
            .collect();
        SchnorrResponsePairing(responses)
    }
}

pub fn verify<E: Pairing>(
    bases_g1: &[E::G1Affine],
    bases_g2: &[E::G2Affine],
    y: &E::TargetField,
    commitment: &SchnorrCommitmentPairing<E>,
    response: &SchnorrResponsePairing<E>,
    challenge: &E::ScalarField,
) -> bool {
    // lhs = e(base1)^response1 * e(base2)^response2 * ...
    // rhs = y somehow mul by challenge? - commitment.com_prime
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_std::test_rng;

    #[test]
    fn test_schnorr_single() {
        let mut rng = test_rng();

        fn check<G: AffineRepr>(rng: &mut impl Rng) {
            let base = G::Group::rand(rng).into_affine();
            let witness = G::ScalarField::rand(rng);
            let y = base.mul(witness).into_affine();
            let blinding = G::ScalarField::rand(rng);

            let commitment = SchnorrProtocol::commit(&[base], rng);
            let mut chal_contrib = Vec::new();
            base.serialize_compressed(&mut chal_contrib).unwrap();
            y.serialize_compressed(&mut chal_contrib).unwrap();
            commitment
                .ti
                .serialize_compressed(&mut chal_contrib)
                .unwrap();

            let challenge = SchnorrProtocol::compute_random_oracle_challenge::<
                G::ScalarField,
                Blake2b512,
            >(&chal_contrib);

            let response = SchnorrProtocol::prove(&commitment, &[witness], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base],
                &y,
                &commitment,
                &response,
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
            let y = (base1.mul(witness1) + base2.mul(witness2)).into_affine();

            let commitment = SchnorrProtocol::commit(&[base1, base2], rng);
            let mut chal_contrib = Vec::new();
            base1.serialize_compressed(&mut chal_contrib).unwrap();
            base2.serialize_compressed(&mut chal_contrib).unwrap();
            y.serialize_compressed(&mut chal_contrib).unwrap();

            commitment
                .ti
                .serialize_compressed(&mut chal_contrib)
                .unwrap();

            let challenge = SchnorrProtocol::compute_random_oracle_challenge::<
                G::ScalarField,
                Blake2b512,
            >(&chal_contrib);
            let response = SchnorrProtocol::prove(&commitment, &[witness1, witness2], &challenge);

            assert!(SchnorrProtocol::verify(
                &[base1, base2],
                &y,
                &commitment,
                &response,
                &challenge
            ));
        }

        check::<G1Affine>(&mut rng);
        check::<G2Affine>(&mut rng);
    }

    #[test]
    fn test_schnorr_tripple() {
        let mut rng = test_rng();

        // Generate bases and witnesses
        let num_witnesses = 3;
        let bases: Vec<G1Affine> = (0..num_witnesses)
            .map(|_| G1Affine::rand(&mut rng))
            .collect();
        let witnesses: Vec<Fr> = (0..num_witnesses).map(|_| Fr::rand(&mut rng)).collect();

        // Compute Commitment
        let y = G1Projective::msm_unchecked(&bases, &witnesses).into_affine();

        // Prover's side
        let commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let challenge = Fr::rand(&mut rng); // In practice, this should be derived from a hash
        let response = SchnorrProtocol::prove(&commitment, &witnesses, &challenge);

        // Verifier's side
        let is_valid = SchnorrProtocol::verify(&bases, &y, &commitment, &response, &challenge);

        assert!(is_valid, "Schnorr proof verification failed");
    }
}
