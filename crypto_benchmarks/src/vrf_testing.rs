use ark_bls12_381::{Bls12_381, Fr, FrConfig, G1Affine, G2Affine};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use ark_std::test_rng;
use ark_std::One;
use ark_std::Zero;
use schnorr::schnorr::SchnorrProtocol;
use serde::ser;

#[derive(Clone)]
pub struct PublicParams {
    pub g: G1Affine, // Generator of G1
}

impl PublicParams {
    pub fn new(rng: &mut impl Rng) -> Self {
        let g = G1Affine::generator(); // Use the canonical generator
        Self { g }
    }
}

pub struct VRFKeyPair {
    pub sk: Fr,       // Secret key
    pub pk: G1Affine, // Public key = g^{sk}
}

impl VRFKeyPair {
    pub fn generate(rng: &mut impl Rng, pp: &PublicParams) -> Self {
        let sk = Fr::rand(rng);
        let pk = pp.g.mul(sk).into_affine();
        Self { sk, pk }
    }
}

pub struct VRFProof {
    pub y: G1Affine,  // VRF output = g^{1/(sk + x)}
    pub T1: G1Affine, // Commitment T1 = g^r
    pub T2: G1Affine, // Commitment T2 = y^r
    pub s: Fr,        // Response s = r + c * (sk + x)
    pub c: Fr,        // challenge
}

impl VRFKeyPair {
    pub fn evaluate(&self, pp: &PublicParams, x: Fr, rng: &mut impl Rng) -> VRFProof {
        // Compute a = sk + x
        let a = self.sk + x;
        let a_inv = a.inverse().expect("sk + x should not be zero");
        let y = pp.g.mul(a_inv).into_affine(); // y = g^{1/(sk + x)}

        // Generate randomness for the proof
        let r = Fr::rand(rng);
        let T1 = pp.g.mul(r).into_affine(); // T1 = g^r
        let T2 = y.mul(r).into_affine(); // T2 = y^r

        let c = Fr::rand(rng);

        // Compute response s = r + c * a
        let s = r + c * a;

        VRFProof { y, T1, T2, s, c }
    }
}

pub fn verify(pp: &PublicParams, pk: G1Affine, x: Fr, proof: &VRFProof) -> bool {
    let VRFProof { y, T1, T2, s, c } = proof;

    // Compute C = pk * g^x = g^{sk} * g^x = g^{sk + x}
    let C = (pk + pp.g.mul(x)).into_affine();

    // Verify the two equations:
    // 1. g^s = T1 * C^c
    let lhs1 = pp.g.mul(*s).into_affine();
    let rhs1 = (T1.into_group() + C.mul(c)).into_affine();

    // 2. y^s = T2 * g^c
    let lhs2 = y.mul(*s).into_affine();
    let rhs2 = (T2.into_group() + pp.g.mul(c)).into_affine();

    lhs1 == rhs1 && lhs2 == rhs2
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_vrf() {
        let mut rng = test_rng();
        let pp = PublicParams::new(&mut rng);
        let keypair = VRFKeyPair::generate(&mut rng, &pp);
        let x = Fr::rand(&mut rng);
        let proof = keypair.evaluate(&pp, x, &mut rng);
        assert!(
            verify(&pp, keypair.pk, x, &proof),
            "VRF verification failed"
        );
    }
}
