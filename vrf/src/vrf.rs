use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// {AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{Field, PrimeField};
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
    pub pk: E::G1Affine,
    pub sk: E::ScalarField,
    pub x: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct PublicKey<E: Pairing> {
    pub pk: E::G1Affine,
}

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

#[derive(Clone, Debug)]
pub struct VRFOutput<E: Pairing> {
    pub y: PairingOutput<E>,
    pub pi_g1: E::G1Affine,
    pub pi_g2: E::G2Affine,
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

    pub fn generate(&self, input: &VRFInput<E>) -> VRFOutput<E> {
        let exponents = (input.x + input.sk)
            .inverse()
            .expect("x + sk should not be zero");

        // pi = g^1/sk+x
        let pi_g1 = self.pp.g1.mul(exponents);
        let pi_g2 = self.pp.g2.mul(exponents);
        let y = E::pairing(&pi_g1, self.pp.g2);
        VRFOutput {
            y,
            pi_g1: pi_g1.into_affine(),
            pi_g2: pi_g2.into_affine(),
        }
    }

    pub fn prove<R: Rng>(
        &self,
        input: &VRFInput<E>,
        output: &VRFOutput<E>,
        rng: &mut R,
    ) -> VrfProof<E> {
        // t_com = g1^r
        let t_commitment = SchnorrProtocol::commit(&[self.pp.g1], rng);
        // t_witness = 1/x+sk
        let t_witness = (input.x + input.sk)
            .inverse()
            .expect("sk + x should not be zero");

        let challenge = E::ScalarField::rand(rng); // update later to hash

        // z = r + challenge * witness... z = r + challenge / x + sk
        let t_responses = SchnorrProtocol::prove(&t_commitment, &[t_witness], &challenge);

        let is_valid = SchnorrProtocol::verify(
            &[self.pp.g1],
            &output.pi_g1,
            &t_commitment,
            &t_responses,
            &challenge,
        );

        assert!(
            is_valid,
            "here in prove function ----- Schnorr proof verification failed"
        );

        let proof = VrfProof {
            t_commitment,
            t_responses,
            challenge,
        };

        // let mut serialized_proof = Vec::new();
        proof
    }

    pub fn verify(&self, input: &VRFInput<E>, output: &VRFOutput<E>, proof: &VrfProof<E>) -> bool {
        // g1^z = g^{r + challenge / x + sk}
        // pi = g^1/sk+x
        // t_commitment = g^r
        // g^z = pi^e * t_commitment
        // g^{r + challenge / x + sk} = g^(1/sk+x)^e * g^r   =   g^r * g^e/x+sk = g^e/x+sk * g^r
        let is_valid = SchnorrProtocol::verify(
            &[self.pp.g1],
            &output.pi_g1,
            &proof.t_commitment,
            &proof.t_responses,
            &proof.challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");
        println!("-------------- isvalid passed");

        // Verify Pairing
        let lhs1 = E::pairing(self.pp.g1.mul(input.x).add(&input.pk), &output.pi_g2);
        // g1 mul x . add pk
        let rhs1 = E::pairing(self.pp.g1, self.pp.g2);
        assert_eq!(lhs1, rhs1, "lhs1 neq rhs1");

        let rhs2 = E::pairing(self.pp.g1, &output.pi_g2);
        assert_eq!(output.y, rhs2, "lhs2 neq rhs2");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    #[test]
    fn test_vrf() {
        use ark_bls12_381::Bls12_381;
        use ark_std::test_rng;

        let mut rng = test_rng();

        // Initialize VRF
        let vrf = VRF::<Bls12_381>::new(&mut rng);

        // Generate keys
        let sk = Fr::rand(&mut rng);
        let pk = vrf.pp.g1.mul(sk).into_affine();

        // Create input
        let x = Fr::rand(&mut rng);
        let input = VRFInput { pk, sk, x };

        // Generate VRF output
        let output = vrf.generate(&input);

        // Generate proof
        let proof = vrf.prove(&input, &output, &mut rng);

        // Verify
        let is_valid = vrf.verify(&input, &output, &proof);
        assert!(is_valid, "VRF verification failed");

        // // Test with incorrect input
        // let incorrect_x = Fr::rand(&mut rng);
        // let incorrect_input = VRFInput {
        //     pk,
        //     sk,
        //     x: incorrect_x,
        // };
        // let is_invalid = vrf.verify(&incorrect_input, &output, &proof);
        // // let is_invalid = vrf.verify(incorrect_input, output, proof);
        // assert!(
        //     !is_invalid,
        //     "VRF verification should fail with incorrect input"
        // );
    }
}
