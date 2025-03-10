// use crate::proofsystem::{CommitmentProof, CommitmentProofError, CommitmentProofs};
use crate::dkg_shamir::generate_shares;
use crate::proofsystem::CommitmentProofs;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Invalid Commit Process")]
    InvalidComputeCommitment,
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SymmetricCommitment<E: Pairing> {
    pub ck: SymmetricCommitmentKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub cm: E::G1Affine,
    pub cm_tilde: E::G2Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SymmetricCommitmentKey<E: Pairing> {
    pub g: E::G1Affine,
    pub ck: Vec<E::G1Affine>,
    pub g_tilde: E::G2Affine,
    pub ck_tilde: Vec<E::G2Affine>,
}

#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Commitment<E: Pairing> {
    pub bases: Vec<E::G1Affine>,
    pub exponents: Vec<E::ScalarField>,
    pub cm: E::G1Affine,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct CommitmentProof<E: Pairing> {
    pub commitment: E::G1Affine,
    pub schnorr_commitment: SchnorrCommitment<E::G1Affine>,
    pub bases: Vec<E::G1Affine>,
    pub challenge: E::ScalarField,
    pub responses: Vec<E::ScalarField>,
}

impl<E: Pairing> Commitment<E> {
    pub fn new(
        h: &E::G1Affine,
        g: &E::G1Affine,
        m: &E::ScalarField,
        r_opt: Option<E::ScalarField>,
        rng: &mut impl Rng,
    ) -> Self {
        let r = match r_opt {
            Some(r_value) => r_value,
            None => E::ScalarField::rand(rng),
        };

        // gen commitment
        let cm = (h.mul(m) + g.mul(r)).into_affine();
        let bases = vec![*h, *g];
        let exponents = vec![*m, r];
        Self {
            bases,
            exponents,
            cm,
        }
    }

    pub fn prove(self, rng: &mut impl Rng) -> Result<Vec<u8>, CommitmentError> {
        let schnorr_commitment = SchnorrProtocol::commit(&self.bases, rng);
        let challenge = E::ScalarField::rand(rng);
        let responses = SchnorrProtocol::prove(&schnorr_commitment, &self.exponents, &challenge);
        let proof: CommitmentProof<E> = CommitmentProof {
            bases: self.bases,
            commitment: self.cm,
            schnorr_commitment,
            challenge,
            responses: responses.0,
        };

        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(serialized_proof)
    }
}

impl<E: Pairing> SymmetricCommitmentKey<E> {
    pub fn new(pp: &PublicParams<E>, y_values: &[E::ScalarField]) -> Self {
        let g = pp.g;
        let g_tilde = pp.g_tilde;
        let ck = y_values
            .iter()
            .map(|y_k| g.mul(y_k).into_affine())
            .collect();

        let ck_tilde = y_values
            .iter()
            .map(|y_k| g_tilde.mul(y_k).into_affine())
            .collect();

        Self {
            g,
            ck,
            g_tilde,
            ck_tilde,
        }
    }

    pub fn get_bases(&self) -> (Vec<E::G1Affine>, Vec<E::G2Affine>) {
        let mut bases = self.ck.clone();
        bases.push(self.g);
        let mut bases_tilde = self.ck_tilde.clone();
        bases_tilde.push(self.g_tilde);

        (bases, bases_tilde)
    }
}

// takes in pp, messages, r. creates cm, cm_tilde by 1. exponentiate each pp.ckg1 with mi and pp.g1 with r, msm together
impl<E: Pairing> SymmetricCommitment<E> {
    pub fn new(
        ck: &SymmetricCommitmentKey<E>,
        messages: &Vec<E::ScalarField>,
        r: &E::ScalarField,
    ) -> Self {
        let cm = g1_commit::<E>(&ck, messages, r);
        let cm_tilde = g2_commit::<E>(&ck, messages, r);
        SymmetricCommitment {
            ck: ck.clone(),              // this clones pp for the commitment
            messages: messages.to_vec(), // this creates its own messages
            r: *r,
            cm,
            cm_tilde,
        }
    }

    pub fn randomize(&self, r_delta: &E::ScalarField) -> Self {
        let new_r = self.r + r_delta;
        let cm_delta = (self.cm + self.ck.g.mul(r_delta)).into_affine();
        let cm_tilde_delta = (self.cm_tilde + self.ck.g_tilde.mul(r_delta)).into_affine();

        Self {
            ck: self.ck.clone(),
            messages: self.messages.clone(),
            r: new_r,
            cm: cm_delta,
            cm_tilde: cm_tilde_delta,
        }
    }

    pub fn randomize_just_g1(&self, r_delta: &E::ScalarField) -> Self {
        let new_r = self.r + r_delta;
        let cm_delta = (self.cm + self.ck.g.mul(r_delta)).into_affine();

        Self {
            ck: self.ck.clone(),
            messages: self.messages.clone(),
            r: new_r,
            cm: cm_delta,
            cm_tilde: self.cm_tilde,
        }
    }

    // get all exponents of the commitment, C([m_1,...,m_n],r)
    pub fn get_exponents(&self) -> Vec<E::ScalarField> {
        let mut exponents: Vec<E::ScalarField> = self.messages.clone();
        exponents.push(self.r.clone());
        exponents
    }

    // // get pok in g1
    // pub fn prove_opening(&self) -> Result<Vec<u8>, CommitmentError> {
    //     CommitmentProofs::pok_commitment_prove(&self)
    // }
}

pub fn g1_commit<E: Pairing>(
    ck: &SymmetricCommitmentKey<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G1Affine {
    assert!(messages.len() <= ck.ck.len(), "m.len should be < ck!");
    let g1_r = ck.g.mul(r);
    let ck = &ck.ck[..messages.len()];

    let temp = E::G1::msm_unchecked(ck, messages);
    temp.add(g1_r).into_affine()
}

pub fn g2_commit<E: Pairing>(
    ck: &SymmetricCommitmentKey<E>,
    messages: &[E::ScalarField],
    r: &E::ScalarField,
) -> E::G2Affine {
    assert!(
        messages.len() <= ck.ck_tilde.len(),
        "message.len > ckg2.len"
    );
    // cut ckg2 to the size of m
    let g2_r = ck.g_tilde.mul(r);
    let ck = &ck.ck_tilde[..messages.len()];
    let temp = E::G2::msm_unchecked(ck, messages);
    temp.add(g2_r).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_randomized_commitment() {
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(None, &mut rng);
        let x = Fr::rand(&mut rng);
        let t = 3;
        let n = 5;
        let l = 4;
        let x_shares = generate_shares(&x, t, n, &mut rng);

        // generate y values [y1,..,yL]
        let mut y_values = Vec::with_capacity(l);
        // [[y1_1,...,y1_L]_1,...,[yL_1,...,yL_L]_k]
        let mut y_shares_by_k = Vec::with_capacity(l);

        // gen l x t degree poly's
        for _ in 0..l {
            let y_k = Fr::rand(&mut rng);
            y_values.push(y_k);
            y_shares_by_k.push(generate_shares(&y_k, t, n, &mut rng));
        }

        let ck = SymmetricCommitmentKey::new(&pp, &y_values);

        // create commitment with messages
        let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = SymmetricCommitment::new(&ck, &messages, &r);

        let challenge = Fr::rand(&mut rng);

        // Let's test opening proof
        let (bases, _) = ck.get_bases();
        let schnorr_commitment = SchnorrProtocol::commit(&bases, &mut rng);
        let responses =
            SchnorrProtocol::prove(&schnorr_commitment, &commitment.get_exponents(), &challenge);

        let is_valid = SchnorrProtocol::verify(
            &bases,
            &commitment.cm,
            &schnorr_commitment,
            &responses,
            &challenge,
        );

        assert!(is_valid);
    }

    #[test]
    fn test_basic_commitment_and_proof() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Generate random base points
        let h = G1Affine::rand(&mut rng);
        let g = G1Affine::rand(&mut rng);

        // Generate a random message
        let m = Fr::rand(&mut rng);

        // Create a commitment
        let commitment = Commitment::<Bls12_381>::new(&h, &g, &m, None, &mut rng);

        // Check that commitment was created correctly
        assert_eq!(commitment.bases.len(), 2, "Should have 2 bases");
        assert_eq!(commitment.exponents.len(), 2, "Should have 2 exponents");
        assert_eq!(commitment.bases[0], h, "First base should be h");
        assert_eq!(commitment.bases[1], g, "Second base should be g");
        assert_eq!(commitment.exponents[0], m, "First exponent should be m");

        // Manually verify the commitment computation
        let r = commitment.exponents[1];
        let expected_cm = (h.mul(&m) + g.mul(&r)).into_affine();
        assert_eq!(
            commitment.cm, expected_cm,
            "Commitment calculation incorrect"
        );

        // Generate a proof
        let serialized_proof = commitment.prove(&mut rng).unwrap();

        // Verify the proof by deserializing and checking
        let proof: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof[..]).unwrap();

        // Verify the proof using Schnorr protocol
        let is_valid = SchnorrProtocol::verify(
            &proof.bases,
            &proof.commitment,
            &proof.schnorr_commitment,
            &SchnorrResponses(proof.responses.clone()),
            &proof.challenge,
        );

        assert!(is_valid, "Proof verification failed");

        // Test with specific blinding factor
        let specific_r = Fr::rand(&mut rng);
        let commitment_with_r =
            Commitment::<Bls12_381>::new(&h, &g, &m, Some(specific_r), &mut rng);

        // Check that the specific blinding was used
        assert_eq!(
            commitment_with_r.exponents[1], specific_r,
            "Custom randomness not used"
        );

        // Generate and verify proof for this commitment too
        let serialized_proof_2 = commitment_with_r.prove(&mut rng).unwrap();
        let proof_2: CommitmentProof<Bls12_381> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof_2[..]).unwrap();

        let is_valid_2 = SchnorrProtocol::verify(
            &proof_2.bases,
            &proof_2.commitment,
            &proof_2.schnorr_commitment,
            &SchnorrResponses(proof_2.responses.clone()),
            &proof_2.challenge,
        );

        assert!(
            is_valid_2,
            "Proof verification failed for commitment with specific randomness"
        );
    }
}
