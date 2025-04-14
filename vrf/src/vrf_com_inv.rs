use ark_bls12_381::{Fr, G1Affine};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul};
use ark_std::rand::Rng;
use ark_std::test_rng;

// Define the proof structure without y
#[derive(Clone)]
pub struct SimplifiedVRFProof {
    cm: G1Affine, // Commitment: g1^sk * g2^x * g^r
    T1: G1Affine, // Commitment for the proof
    Ty: G1Affine, // Commitment for y
    z_sk: Fr,     // Response for sk
    z_x: Fr,      // Response for x
    z_r: Fr,      // Response for r
    z_sk_x: Fr,   // Response for m = sk + x
    c: Fr,        // Challenge
}

// Generate the secret key sk
pub fn vrf_gen<R: Rng>(rng: &mut R) -> Fr {
    Fr::rand(rng)
}

// Evaluate the VRF to compute y
pub fn vrf_eval(g: G1Affine, sk: Fr, x: Fr) -> G1Affine {
    let sk_x = sk + x;
    let sk_x_inv = sk_x.inverse().unwrap();
    g.mul(sk_x_inv).into_affine()
}

// Generate the proof π along with y
pub fn vrf_prove<R: Rng>(
    g1: G1Affine,
    g2: G1Affine,
    g: G1Affine,
    sk: Fr,
    x: Fr,
    y: G1Affine,
    rng: &mut R,
) -> SimplifiedVRFProof {
    let r = Fr::rand(rng);
    let sk_x = sk + x;
    let cm = (g1.mul(sk) + g2.mul(x) + g.mul(r)).into_affine();
    let a_sk = Fr::rand(rng);
    let a_x = Fr::rand(rng);
    let a_r = Fr::rand(rng);
    let a_sk_x = a_sk + a_x;
    let T1 = (g1.mul(a_sk) + g2.mul(a_x) + g.mul(a_r)).into_affine();
    let Ty = y.mul(a_sk_x).into_affine();
    let c = Fr::rand(rng);
    let z_sk = a_sk + c * sk;
    let z_x = a_x + c * x;
    let z_r = a_r + c * r;
    let z_sk_x = a_sk_x + c * sk_x;
    let proof = SimplifiedVRFProof {
        cm,
        T1,
        Ty,
        z_sk,
        z_x,
        z_r,
        z_sk_x,
        c,
    };
    (proof)
}

// Verify the proof
pub fn vrf_verify(
    g1: G1Affine,
    g2: G1Affine,
    g: G1Affine,
    y: G1Affine,
    proof: &SimplifiedVRFProof,
) -> bool {
    let lhs_T1 = proof.T1 + proof.cm.mul(proof.c);
    let rhs_T1 = g1.mul(proof.z_sk) + g2.mul(proof.z_x) + g.mul(proof.z_r);
    if lhs_T1 != rhs_T1.into_affine() {
        return false;
    }
    let lhs_Ty = proof.Ty + g.mul(proof.c);
    let rhs_Ty = y.mul(proof.z_sk_x);
    if lhs_Ty != rhs_Ty.into_affine() {
        return false;
    }
    proof.z_sk_x == proof.z_sk + proof.z_x
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Affine;
    use ark_ff::UniformRand;

    #[test]
    fn test_simplified_vrf() {
        let mut rng = test_rng();
        let g1 = G1Affine::rand(&mut rng);
        let g2 = G1Affine::rand(&mut rng);
        let g = G1Affine::rand(&mut rng);
        let sk = vrf_gen(&mut rng);
        let x = Fr::rand(&mut rng);
        let y = vrf_eval(g, sk, x);
        let proof = vrf_prove(g1, g2, g, sk, x, y, &mut rng);
        assert!(vrf_verify(g1, g2, g, y, &proof), "VRF verification failed");
    }
}
