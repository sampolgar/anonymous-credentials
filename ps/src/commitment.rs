use crate::keygen::PublicKey;
use crate::proofsystem::{CommitmentProof, CommitmentProofError, CommitmentProofs};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

#[derive(Clone, Debug)]
pub struct Commitment<E: Pairing> {
    pub pp: PublicParams<E>,
    pub pk: PublicKey<E>,
    pub messages: Vec<E::ScalarField>, // Message vector
    pub t: E::ScalarField,             // Blinding factor
    pub commitment: E::G1Affine,       // Commitment value
}

impl<E: Pairing> Commitment<E> {
    pub fn new(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        messages: &[E::ScalarField],
        t: &E::ScalarField,
    ) -> Self {
        assert_eq!(messages.len(), pp.n, "Invalid message count");

        // Compute the commitment: C = g1^t · Y1^m1 · ... · Yn^mn
        let bases = &pk.y_g1;
        let commitment = compute_commitment_g1::<E>(t, &pp.g1, messages, bases);

        Self {
            pp: pp.clone(),
            pk: pk.clone(),
            messages: messages.to_vec(),
            t: *t,
            commitment: commitment,
        }
    }

    // get all exponents of the commitment, C([m_1,...,m_n],r)
    pub fn get_exponents(&self) -> Vec<E::ScalarField> {
        let mut exponents: Vec<E::ScalarField> = self.messages.clone();
        exponents.push(self.t.clone());
        exponents
    }

    // get all exponents of the commitment, C([m_1,...,m_n],r)
    pub fn get_bases(&self) -> Vec<E::G1Affine> {
        let mut bases: Vec<E::G1Affine> = self.pk.y_g1.clone();
        bases.push(self.pp.g1.clone());
        bases
    }

    // get pok in g1
    pub fn prove_opening(&self) -> Result<Vec<u8>, CommitmentProofError> {
        CommitmentProofs::pok_commitment_prove(&self)
    }
}

// Helper function for commitment computation
pub fn compute_commitment_g1<E: Pairing>(
    t: &E::ScalarField,
    g1: &E::G1Affine,
    messages: &[E::ScalarField],
    bases: &[E::G1Affine],
) -> E::G1Affine {
    // Compute Y1^m1 · ... · Yn^mn using multi-scalar multiplication
    let msm = E::G1::msm_unchecked(&bases[..messages.len()], messages);

    // Add g1^t to complete the commitment
    let g1t = g1.mul(*t);
    (msm + g1t).into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::gen_keys;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_commitment() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &context, &mut rng);
        let (_, pk) = gen_keys(&pp, &mut rng);

        // Create random messages and blinding factor
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let t = Fr::rand(&mut rng);

        // Create commitment
        let commitment = Commitment::new(&pp, &pk, &messages, &t);

        // Verify commitment was created
        assert!(
            !commitment.commitment.is_zero(),
            "Commitment should not be zero"
        );
    }
}
