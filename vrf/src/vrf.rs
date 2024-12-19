use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    test_rng, One, UniformRand, Zero,
};
use core::marker::PhantomData;
use rayon::prelude::*;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

#[derive(Clone, Debug)]
pub struct VRFInput<E: Pairing> {
    pub x: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub pk: E::G2Affine,
}

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct VRFOutput<E: Pairing> {
    pub y: E::TargetField,
    pub pi: E::G1Affine,
}

pub struct VRFPublicParams<E: Pairing> {
    pub g1: E::G1Affine,
    pub g2: E::G2Affine,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VrfProof<E: Pairing> {
    pub t_commitment: SchnorrCommitment<E::G1Affine>,
    pub t_responses: SchnorrResponses<E::G1Affine>,
    pub challenge: E::ScalarField,
}
pub struct VRF<E: Pairing> {
    _phantom: PhantomData<E>,
    pp: VRFPublicParams<E>,
}

impl<E: Pairing> VRF<E> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G2Affine::rand(rng);
        VRF {
            _phantom: PhantomData,
            pp: VRFPublicParams { g1, g2 },
        }
    }

    pub fn generate_keys<R: Rng>(&self, rng: &mut R) -> (SecretKey<E>, PublicKey<E>) {
        let sk = E::ScalarField::rand(rng);
        let pk = self.pp.g2.mul(sk).into_affine();
        (SecretKey { sk }, PublicKey { pk })
    }

    pub fn generate(
        &self,
        input: &VRFInput<E>,
        sk: &SecretKey<E>,
    ) -> Result<VRFOutput<E>, &'static str> {
        let exponent = (input.x + sk.sk).inverse().ok_or("x + sk is zero")?;

        let pi = self.pp.g1.mul(exponent).into_affine();
        let y = E::pairing(pi, self.pp.g2).0;

        Ok(VRFOutput { y, pi })
    }

    // prove knowledge of sk such that pi_sk(x) = g^1/sk+x(proof of correctness)
    pub fn prove<R: Rng>(
        &self,
        input: &VRFInput<E>,
        sk: &SecretKey<E>,
        output: &VRFOutput<E>,
        rng: &mut R,
    ) -> Result<VrfProof<E>, &'static str> {
        // t_witness = 1/x+sk
        let t_witness = (input.x + sk.sk).inverse().ok_or("sk + x is zero")?;

        // t_com = g1^r
        let t_commitment = SchnorrProtocol::commit(&[self.pp.g1], rng);

        let challenge = E::ScalarField::rand(rng); // update later to hash

        // z = r + challenge * witness... z = r + challenge / x + sk
        let t_responses = SchnorrProtocol::prove(&t_commitment, &[t_witness], &challenge);

        Ok(VrfProof {
            t_commitment,
            t_responses,
            challenge,
        })
    }

    pub fn verify(
        &self,
        input: &VRFInput<E>,
        pk: &PublicKey<E>,
        output: &VRFOutput<E>,
        proof: &VrfProof<E>,
    ) -> bool {
        let is_schnorr_valid = SchnorrProtocol::verify(
            &[self.pp.g1],
            &output.pi,
            &proof.t_commitment.com_t,
            &proof.t_responses,
            &proof.challenge,
        );

        if !is_schnorr_valid {
            return false;
        }

        println!("-------------- schnorr passed");

        // e(pi, g2^x * PK) = e(g1,g2)
        // y = (pi, g2)
        let lhs1 = E::pairing(&output.pi, self.pp.g2.mul(input.x).add(&pk.pk));
        let rhs1 = E::pairing(self.pp.g1, self.pp.g2);

        let rhs2 = E::pairing(&output.pi, self.pp.g2);

        let is_valid_pairing = lhs1 == rhs1 && output.y == rhs2.0;

        if !is_valid_pairing {
            print!("in not valid pairing");
            return false;
        }
        println!("-------------- pairing passed");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    #[test]
    fn test_vrf() {
        let mut rng = test_rng();

        // Initialize VRF
        let vrf = VRF::<Bls12_381>::new(&mut rng);

        // Generate keys
        let sk = SecretKey {
            sk: Fr::rand(&mut rng),
        };
        let pk = PublicKey {
            pk: vrf.pp.g2.mul(sk.sk).into_affine(),
        };

        // Create input
        let x = Fr::rand(&mut rng);
        let input = VRFInput { x };

        // Generate VRF output
        let output = vrf
            .generate(&input, &sk)
            .expect("Failed to generate VRF output");

        // Generate proof
        let proof = vrf
            .prove(&input, &sk, &output, &mut rng)
            .expect("Failed to generate proof");

        // Verify
        let is_valid = vrf.verify(&input, &pk, &output, &proof);
        assert!(is_valid, "VRF verification failed");
        println!("vrf passed -----------------------------------------");
    }
}
