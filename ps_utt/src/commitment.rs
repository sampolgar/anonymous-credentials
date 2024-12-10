use crate::ps_helpers::{g1_commit, g2_commit};
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;

#[derive(Clone)]
pub struct Commitment<E: Pairing> {
    pp: PublicParams<E>,
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
    cmg1: E::G1Affine,
    cmg2: E::G2Affine,
}

// takes in pp, messages, r. creates cmg1, cmg2 by 1. exponentiate each pp.ckg1 with mi and pp.g1 with r, msm together

impl<E: Pairing> Commitment<E> {
    pub fn new(pp: &PublicParams<E>, messages: &Vec<E::ScalarField>, r: &E::ScalarField) -> Self {
        let cmg1 = g1_commit::<E>(&pp.ckg1, &pp.g1, &messages, &r);
        let cmg2 = g2_commit::<E>(&pp.ckg2, &pp.g2, &messages, &r);
        Commitment {
            pp: pp.clone(),              // this clones pp for the commitment
            messages: messages.to_vec(), // this creates its own messages
            r: *r,
            cmg1,
            cmg2,
        }
    }

    pub fn create_randomized(&self, r_delta: &E::ScalarField) -> Self {
        let new_r = self.r + r_delta;
        let cmg1_delta = (self.cmg1 + self.pp.g1.mul(r_delta)).into_affine();
        let cmg2_delta = (self.cmg2 + self.pp.g2.mul(r_delta)).into_affine();

        Self {
            pp: self.pp.clone(),
            messages: self.messages.clone(),
            r: new_r,
            cmg1: cmg1_delta,
            cmg2: cmg2_delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_randomized_commitment() {
        let n = 4;
        let mut rng = ark_std::test_rng();
        let r = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&n, &mut rng);
        let messages: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let commitment = Commitment::new(&pp, &messages, &r);

        println!("r: {}", r);
        let r_delta = Fr::rand(&mut rng);
        println!("r_delta: {}", r_delta);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        println!("my summed: : {}", r + r_delta);
        println!("summed r: {}", randomized_commitment.r);

        let cmg1 = commitment.cmg1.add(pp.g1.mul(r_delta));
        let cmg1_rand = randomized_commitment.cmg1;
        assert_eq!(cmg1, cmg1_rand, "cmg1 and randomized aren't equal");
    }
}
