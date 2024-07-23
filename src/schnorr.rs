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
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, vec::Vec, UniformRand};
use blake2::Blake2b512;
use digest::Digest;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrCommitment<G: AffineRepr> {
    pub blindings: Vec<G::ScalarField>,
    pub t: G,
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
        let t = G::Group::msm_unchecked(bases, &blindings).into_affine();
        SchnorrCommitment { blindings, t }
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
        let rhs = (commitment.t + y.mul(*challenge)).into_affine();
        lhs == rhs
    }

    pub fn compute_random_oracle_challenge<F: PrimeField, D: Digest>(challenge_bytes: &[u8]) -> F {
        let mut hash_output = D::digest(challenge_bytes);
        F::from_be_bytes_mod_order(&hash_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_std::test_rng;

    #[test]
    fn test_schnorr_protocol() {
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
                .t
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
                .t
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

    // #[test]
    // fn test_discrete_log_proof_in_pairing_group() {
    //     let mut rng = test_rng();

    //     fn check<G1: AffineRepr, G2: AffineRepr>(rng: &mut impl Rng)
    //     where
    //         Bls12_381: Pairing<G1 = G1::Group, G2 = G2::Group>,
    //     {
    //         let base = G2::Group::rand(rng).into_affine();
    //         let witness = G1::Group::rand(rng).into_affine();
    //         let y = Bls12_381::pairing(witness, base);

    //         let blinding = G1::Group::rand(rng).into_affine();
    //         let t = Bls12_381::pairing(
    //             Bls12_381::prepare_g1(&blinding),
    //             Bls12_381::prepare_g2(&base),
    //         );

    //         let commitment = SchnorrCommitment {
    //             blindings: vec![blinding.into()],
    //             t,
    //         };

    //         let mut chal_contrib = Vec::new();
    //         base.serialize_compressed(&mut chal_contrib).unwrap();
    //         y.serialize_compressed(&mut chal_contrib).unwrap();
    //         t.serialize_compressed(&mut chal_contrib).unwrap();

    //         let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_contrib);
    //         let response = SchnorrProtocol::prove(&commitment, &[witness.into()], &challenge);

    //         let response_group = G1::Group::from(response.0[0]).into_affine();
    //         let lhs = Bls12_381::pairing(
    //             Bls12_381::prepare_g1(&response_group),
    //             Bls12_381::prepare_g2(&base),
    //         );
    //         let rhs = t + y * challenge;

    //         assert_eq!(lhs, rhs);
    //     }

    //     check::<G1Affine, G2Affine>(&mut rng);
    //     check::<G2Affine, G1Affine>(&mut rng);
    // }
}
