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

// public parameters have g1, g2, \tilde{h},
#[derive(Clone)]
pub struct PublicParams<E: Pairing> {
    pub g: E::G1Affine,
    pub g1: E::G1Affine,
    pub g2: E::G1Affine,
    pub g6: E::G1Affine,
    pub h: E::G1Affine,
    pub h_tilde: E::G2Affine,
    pub w_tilde: E::G2Affine,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let g = E::G1Affine::rand(rng);
        let g1 = E::G1Affine::rand(rng);
        let g2 = E::G1Affine::rand(rng);
        let g6 = E::G1Affine::rand(rng);
        let h_scalar = E::ScalarField::rand(rng);
        let h = E::G1Affine::generator().mul(h_scalar).into_affine();
        let h_tilde = E::G2Affine::generator().mul(h_scalar).into_affine();
        let w_tilde = E::G2Affine::rand(rng);
        Self {
            g,
            g1,
            g2,
            g6,
            h,
            h_tilde,
            w_tilde,
        }
    }

    pub fn get_ccm_bases(&self) -> Vec<E::G1Affine> {
        let mut bases = Vec::new();
        bases.push(self.g1);
        bases.push(self.g2);
        bases.push(self.g);
        bases
    }

    pub fn get_rcm_bases(&self) -> Vec<E::G1Affine> {
        let mut bases = Vec::new();
        bases.push(self.g1);
        bases.push(self.g6);
        bases.push(self.g);
        bases
    }
}
pub struct PairingVRFProof {
    nullif: G1Affine,
    ccm: G1Affine,
    rcm: G1Affine,
    vk: G2Affine,
    y: PairingOutput<Bls12_381>,
    X1: G1Affine,
    X3: G1Affine,
    X4: G2Affine,
    X5: PairingOutput<Bls12_381>,
    a1: Fr,
    a2: Fr,
    a4: Fr,
    a6: Fr,
    a7: Fr,
    a8: Fr,
    c: Fr,
}

pub fn pairing_vrf_evaluate<R: Rng>(
    pp: &PublicParams<Bls12_381>,
    s_sender: Fr,
    pid_sender: Fr,
    sn: Fr,
    r: Fr,
    a_prime: Fr,
    t: Fr,
    rng: &mut R,
) -> (PairingVRFProof, PairingOutput<Bls12_381>) {
    let exponent = s_sender + sn;
    let exponent_inv = exponent.inverse().unwrap();
    let nullif = pp.h.mul(exponent_inv).into_affine();
    let vk = (pp.h_tilde.mul(exponent) + pp.w_tilde.mul(t)).into_affine();
    let q = Pairing::pairing(nullif, pp.w_tilde);
    let y = q * t;

    let ccm = (pp.g1.mul(pid_sender) + pp.g2.mul(sn) + pp.g.mul(r)).into_affine();
    let rcm = (pp.g1.mul(pid_sender) + pp.g6.mul(s_sender) + pp.g.mul(a_prime)).into_affine();

    let x1 = Fr::rand(rng);
    let x2 = Fr::rand(rng);
    let x4 = Fr::rand(rng);
    let x6 = Fr::rand(rng);
    let x7 = Fr::rand(rng);
    let x8 = Fr::rand(rng);

    let X1 = (pp.g1.mul(x1) + pp.g2.mul(x2) + pp.g.mul(x4)).into_affine();
    let X3 = (pp.g1.mul(x1) + pp.g6.mul(x6) + pp.g.mul(x7)).into_affine();
    let X4 = (pp.h_tilde.mul(x6) + pp.h_tilde.mul(x2) + pp.w_tilde.mul(x8)).into_affine();
    let X5 = q * x8;

    let c = Fr::rand(rng); // In practice, hash X1, X3, X4, X5

    let a1 = x1 + c * pid_sender;
    let a2 = x2 + c * sn;
    let a4 = x4 + c * r;
    let a6 = x7 + c * a_prime;
    let a7 = x6 + c * s_sender;
    let a8 = x8 + c * t;

    let proof = PairingVRFProof {
        nullif,
        ccm,
        rcm,
        vk,
        y,
        X1,
        X3,
        X4,
        X5,
        a1,
        a2,
        a4,
        a6,
        a7,
        a8,
        c,
    };
    (proof, y)
}

pub fn pairing_vrf_verify(pp: &PublicParams<Bls12_381>, proof: &PairingVRFProof) -> bool {
    let lhs_pairing = Pairing::pairing(proof.nullif, proof.vk);
    let rhs_pairing = Pairing::pairing(pp.h, pp.h_tilde) + proof.y;
    if lhs_pairing != rhs_pairing {
        return false;
    }

    let lhs_ccm = (proof.ccm.mul(proof.c) + proof.X1).into_affine();
    let rhs_ccm = (pp.g1.mul(proof.a1) + pp.g2.mul(proof.a2) + pp.g.mul(proof.a4)).into_affine();
    if lhs_ccm != rhs_ccm {
        return false;
    }

    let lhs_rcm = (proof.rcm.mul(proof.c) + proof.X3).into_affine();
    let rhs_rcm = (pp.g1.mul(proof.a1) + pp.g6.mul(proof.a7) + pp.g.mul(proof.a6)).into_affine();
    if lhs_rcm != rhs_rcm {
        return false;
    }

    let lhs_vk = (proof.vk.mul(proof.c) + proof.X4).into_affine();
    let rhs_vk = (pp.h_tilde.mul(proof.a7) + pp.h_tilde.mul(proof.a2) + pp.w_tilde.mul(proof.a8))
        .into_affine();
    if lhs_vk != rhs_vk {
        return false;
    }

    let q = Pairing::pairing(proof.nullif, pp.w_tilde);
    let lhs_y = proof.y.mul(proof.c) + proof.X5;
    let rhs_y = q * proof.a8;
    lhs_y == rhs_y
}

pub struct NonPairingVRFProof {
    cm1: G1Affine,
    cm2: G1Affine,
    cm3: G1Affine,
    cm4: G1Affine,
    cm5: G1Affine,
    cm6: G1Affine,
    T1: G1Affine,
    T2: G1Affine,
    T3: G1Affine,
    T4: G1Affine,
    T5: G1Affine,
    T6: G1Affine,
    z_pid_sender: Fr,
    z_s_sender: Fr,
    z_sn: Fr,
    z_r1: Fr,
    z_r2: Fr,
    z_r3: Fr,
    z_exponent_s_sn_inv: Fr,
    z_r4: Fr,
    z_r5: Fr,
    z_r6: Fr,
    c: Fr,
}

pub fn non_pairing_vrf_evaluate<R: Rng>(
    g1: G1Affine,
    g2: G1Affine,
    g3: G1Affine,
    g4: G1Affine,
    g5: G1Affine,
    g: G1Affine,
    pid_sender: Fr,
    s_sender: Fr,
    sn: Fr,
    r1: Fr,
    r2: Fr,
    r3: Fr,
    r4: Fr,
    r5: Fr,
    rng: &mut R,
) -> (NonPairingVRFProof, G1Affine) {
    let exponent_s_sn = s_sender + sn;
    let exponent_s_sn_inv = exponent_s_sn.inverse().unwrap();
    let r6 = (r3 / exponent_s_sn) + r5;

    let cm1 = (g1.mul(pid_sender) + g2.mul(s_sender) + g.mul(r1)).into_affine();
    let cm2 = (g1.mul(pid_sender) + g3.mul(sn) + g.mul(r2)).into_affine();
    let cm3 = (g4.mul(exponent_s_sn) + g.mul(r3)).into_affine();
    let cm4 = (g5.mul(exponent_s_sn_inv) + g.mul(r4)).into_affine();
    let cm5 = (cm3.mul(exponent_s_sn_inv) + g.mul(r5)).into_affine();
    let cm6 = g.mul(r6).into_affine();

    let a_pid_sender = Fr::rand(rng);
    let a_s_sender = Fr::rand(rng);
    let a_sn = Fr::rand(rng);
    let a_exponent_s_sn_inv = Fr::rand(rng);
    let a_r1 = Fr::rand(rng);
    let a_r2 = Fr::rand(rng);
    let a_r3 = Fr::rand(rng);
    let a_r4 = Fr::rand(rng);
    let a_r5 = Fr::rand(rng);
    let a_r6 = Fr::rand(rng);

    let T1 = (g1.mul(a_pid_sender) + g2.mul(a_s_sender) + g.mul(a_r1)).into_affine();
    let T2 = (g1.mul(a_pid_sender) + g3.mul(a_sn) + g.mul(a_r2)).into_affine();
    let T3 = (g4.mul(a_s_sender + a_sn) + g.mul(a_r3)).into_affine();
    let T4 = (g5.mul(a_exponent_s_sn_inv) + g.mul(a_r4)).into_affine();
    let T5 = (cm3.mul(a_exponent_s_sn_inv) + g.mul(a_r5)).into_affine();
    let T6 = g.mul(a_r6).into_affine();

    let c = Fr::rand(rng); // In practice, hash T1 to T6

    let z_pid_sender = a_pid_sender + c * pid_sender;
    let z_s_sender = a_s_sender + c * s_sender;
    let z_sn = a_sn + c * sn;
    let z_r1 = a_r1 + c * r1;
    let z_r2 = a_r2 + c * r2;
    let z_r3 = a_r3 + c * r3;
    let z_r4 = a_r4 + c * r4;
    let z_r5 = a_r5 + c * r5;
    let z_r6 = a_r6 + c * r6;
    let z_exponent_s_sn_inv = a_exponent_s_sn_inv + c * exponent_s_sn_inv;

    let proof = NonPairingVRFProof {
        cm1,
        cm2,
        cm3,
        cm4,
        cm5,
        cm6,
        T1,
        T2,
        T3,
        T4,
        T5,
        T6,
        z_pid_sender,
        z_s_sender,
        z_sn,
        z_r1,
        z_r2,
        z_r3,
        z_exponent_s_sn_inv,
        z_r4,
        z_r5,
        z_r6,
        c,
    };
    (proof, g4) // g4 as proxy output via cm5 - cm6
}

pub fn non_pairing_vrf_verify(
    g1: G1Affine,
    g2: G1Affine,
    g3: G1Affine,
    g4: G1Affine,
    g5: G1Affine,
    g: G1Affine,
    proof: &NonPairingVRFProof,
) -> bool {
    if (proof.cm1.mul(proof.c) + proof.T1)
        != (g1.mul(proof.z_pid_sender) + g2.mul(proof.z_s_sender) + g.mul(proof.z_r1)).into_affine()
    {
        return false;
    }
    if (proof.cm2.mul(proof.c) + proof.T2)
        != (g1.mul(proof.z_pid_sender) + g3.mul(proof.z_sn) + g.mul(proof.z_r2)).into_affine()
    {
        return false;
    }
    if (proof.cm3.mul(proof.c) + proof.T3)
        != (g4.mul(proof.z_s_sender + proof.z_sn) + g.mul(proof.z_r3)).into_affine()
    {
        return false;
    }
    if (proof.cm4.mul(proof.c) + proof.T4)
        != (g5.mul(proof.z_exponent_s_sn_inv) + g.mul(proof.z_r4)).into_affine()
    {
        return false;
    }
    if (proof.cm5.mul(proof.c) + proof.T5)
        != (proof.cm3.mul(proof.z_exponent_s_sn_inv) + g.mul(proof.z_r5)).into_affine()
    {
        return false;
    }
    if (proof.cm6.mul(proof.c) + proof.T6) != g.mul(proof.z_r6).into_affine() {
        return false;
    }
    proof.cm5.add(proof.cm6.neg()) == g4
}

#[cfg(test)]

mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, FrConfig, G1Affine};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use serde::ser;
    #[test]
    fn test_pairing_vrf() {
        // Initialize a deterministic RNG for reproducibility
        let mut rng = test_rng();

        // Set up public parameters
        let pp = PublicParams::<Bls12_381>::new(&mut rng);

        // Generate random field elements as inputs
        let s_sender = Fr::rand(&mut rng);
        let pid_sender = Fr::rand(&mut rng);
        let sn = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let a_prime = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);

        // Evaluate the VRF to get proof and output
        let (proof, _y) =
            pairing_vrf_evaluate(&pp, s_sender, pid_sender, sn, r, a_prime, t, &mut rng);

        // Verify the proof
        assert!(
            pairing_vrf_verify(&pp, &proof),
            "Pairing VRF verification failed"
        );
    }

    #[test]
    fn test_non_pairing_vrf() {
        // Initialize a deterministic RNG
        let mut rng = test_rng();

        // Generate random generators
        let g1 = G1Affine::rand(&mut rng);
        let g2 = G1Affine::rand(&mut rng);
        let g3 = G1Affine::rand(&mut rng);
        let g4 = G1Affine::rand(&mut rng);
        let g5 = G1Affine::rand(&mut rng);
        let g = G1Affine::rand(&mut rng);

        // Generate random field elements as inputs
        let pid_sender = Fr::rand(&mut rng);
        let s_sender = Fr::rand(&mut rng);
        let sn = Fr::rand(&mut rng);
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);
        let r3 = Fr::rand(&mut rng);
        let r4 = Fr::rand(&mut rng);
        let r5 = Fr::rand(&mut rng);

        // Evaluate the VRF to get proof and output
        let (proof, _output) = non_pairing_vrf_evaluate(
            g1, g2, g3, g4, g5, g, pid_sender, s_sender, sn, r1, r2, r3, r4, r5, &mut rng,
        );

        // Verify the proof
        assert!(
            non_pairing_vrf_verify(g1, g2, g3, g4, g5, g, &proof),
            "Non-pairing VRF verification failed"
        );
    }
}
