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
use schnorr::schnorr::SchnorrProtocol;
use thiserror::Error;

/// Possible errors that can occur during commitment proof operations
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
pub struct Commitment<E: Pairing> {
    pub ck: CommitmentKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub r: E::ScalarField,
    pub cm: E::G1Affine,
    pub cm_tilde: E::G2Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentKey<E: Pairing> {
    pub g: E::G1Affine,
    pub ck: Vec<E::G1Affine>,
    pub g_tilde: E::G2Affine,
    pub ck_tilde: Vec<E::G2Affine>,
}

impl<E: Pairing> CommitmentKey<E> {
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
impl<E: Pairing> Commitment<E> {
    pub fn new(ck: &CommitmentKey<E>, messages: &Vec<E::ScalarField>, r: &E::ScalarField) -> Self {
        let cm = g1_commit::<E>(&ck, messages, r);
        let cm_tilde = g2_commit::<E>(&ck, messages, r);
        Commitment {
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
    ck: &CommitmentKey<E>,
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
    ck: &CommitmentKey<E>,
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
    use ark_bls12_381::{Bls12_381, Fr};

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

        let ck = CommitmentKey::new(&pp, &y_values);

        // create commitment with messages
        let messages: Vec<Fr> = (0..l).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&ck, &messages, &r);

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
}
