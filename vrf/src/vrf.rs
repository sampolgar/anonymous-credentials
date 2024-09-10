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

    pub fn generate(
        &self,
        input: &VRFInput<E>,
        sk: &SecretKey<E>,
    ) -> Result<VRFOutput<E>, &'static str> {
        let exponents = (input.x + sk.sk).inverse().ok_or("x + sk is zero")?;

        // pi = g^1/sk+x
        let pi = self.pp.g1.mul(exponents).into_affine();
        Ok(VRFOutput { pi })
    }

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
        // g1^z = g^{r + challenge / x + sk}
        // pi = g^1/sk+x
        // t_commitment = g^r
        // g^z = pi^e * t_commitment
        // g^{r + challenge / x + sk} = g^(1/sk+x)^e * g^r   =   g^r * g^e/x+sk = g^e/x+sk * g^r
        let is_schnorr_valid = SchnorrProtocol::verify(
            &[self.pp.g1],
            &output.pi,
            &proof.t_commitment,
            &proof.t_responses,
            &proof.challenge,
        );

        assert!(is_schnorr_valid, "Schnorr proof verification failed");
        println!("-------------- isvalid passed");
        //  if !is_schnorr_valid {
        //     return false;
        // }
        // Verify Pairing. Lhs: pi = g^1/sk+x. Rhs: g2.mul(x).add(g2^sk)
        let lhs = E::pairing(
            &output.pi,
            &self
                .pp
                .g2
                .mul(input.x)
                .add(&pk.pk.into_group())
                .into_affine(),
        );
        let rhs = E::pairing(&self.pp.g1, &self.pp.g2);

        // // Verify Pairing
        // let lhs1 = E::pairing(self.pp.g1.mul(input.x).add(&input.pk), &output.pi_g2);
        // // g1 mul x . add pk
        // let rhs1 = E::pairing(self.pp.g1, self.pp.g2);
        // assert_eq!(lhs1, rhs1, "lhs1 neq rhs1");

        // let rhs2 = E::pairing(self.pp.g1, &output.pi_g2);
        // assert_eq!(output.y, rhs2, "lhs2 neq rhs2");
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
