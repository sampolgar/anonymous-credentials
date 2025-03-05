use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use ark_std::test_rng;
use ark_std::One;
use ark_std::Zero;
use schnorr::schnorr::SchnorrProtocol;

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
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, FrConfig, G1Affine};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use serde::ser;

    #[test]
    fn test_utt_vrf() {
        let mut rng = test_rng();
        let s_sender = Fr::rand(&mut rng);
        let pid_sender = Fr::rand(&mut rng);
        let sn = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let a_prime = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);

        let pp = PublicParams::<Bls12_381>::new(&mut rng);
        let exponent = s_sender + sn;
        // let exponent_inv2 = -exponent;
        let exponent_inv = exponent.inverse().expect("exponent should be invertible");
        // assert_eq!(
        //     exponent_inv, exponent_inv2,
        //     "inverse exponents aren't equal"
        // );
        let nullif = pp.h.mul(exponent_inv);
        let vk = pp.h_tilde.mul(s_sender + sn) + pp.w_tilde.mul(t);
        let q: PairingOutput<Bls12_381> = Pairing::pairing(nullif, pp.w_tilde);
        let y = q * t;

        let ccm = pp.g1.mul(pid_sender) + pp.g2.mul(sn) + pp.g.mul(r);
        let rcm = pp.g1.mul(pid_sender) + pp.g6.mul(s_sender) + pp.g.mul(a_prime);

        let x1 = Fr::rand(&mut rng);
        let x2 = Fr::rand(&mut rng);
        let x4 = Fr::rand(&mut rng);
        // let x5 = Fr::rand(&mut rng);
        let x6 = Fr::rand(&mut rng);
        let x7 = Fr::rand(&mut rng);
        let x8 = Fr::rand(&mut rng);

        let X1 = pp.g1.mul(x1) + pp.g2.mul(x2) + pp.g.mul(x4);
        // let X2 = pp.g3.mul(x3) + pp.g.mul(x5);
        // not using X3 like they are
        let X3 = pp.g1.mul(x1) + pp.g6.mul(x6) + pp.g.mul(x7);
        let X4 = pp.h_tilde.mul(x6) + pp.h_tilde.mul(x2) + pp.w_tilde.mul(x8);
        let X5 = q * x8;

        let c = Fr::rand(&mut rng);

        let a1 = x1 + c.mul(pid_sender);
        let a2 = x2 + c.mul(sn);
        // let a3 = x3 + c.mul(); /not needed
        let a4 = x4 + c.mul(r);
        // let a5 = x5 + c. /not needed
        let a6 = x7 + c.mul(a_prime);
        let a7 = x6 + c.mul(s_sender);
        let a8 = x8 + c.mul(t);

        // Verify
        let lhs_pairing: PairingOutput<Bls12_381> = Pairing::pairing(nullif, vk);
        let rhs_pairing: PairingOutput<Bls12_381> = Pairing::pairing(pp.h, pp.h_tilde) + y;
        assert_eq!(lhs_pairing, rhs_pairing, "pairing not equal");

        let lhs_ccm = ccm.mul(c) + X1;
        let rhs_ccm = pp.g1.mul(a1) + pp.g2.mul(a2) + pp.g.mul(a4);
        assert_eq!(lhs_ccm, rhs_ccm, "lhsccm neq rhsccm");

        let lhs_rcm = rcm.mul(c) + X3;
        let rhs_rcm = pp.g1.mul(a1) + pp.g6.mul(a7) + pp.g.mul(a6);
        assert_eq!(lhs_rcm, rhs_rcm, "lhsrcm neq rhsrcm");

        let lhs_vk = vk.mul(c) + X4;
        let rhs_vk = pp.h_tilde.mul(a7) + pp.h_tilde.mul(a2) + pp.w_tilde.mul(a8);
        assert_eq!(lhs_vk, rhs_vk, "lhs_vk neq rhs_vk");

        let lhs_y = (y * c) + X5;
        let rhs_y = q * a8;
        assert_eq!(lhs_y, rhs_y, "lhs_y neq rhs_y");
    }

    #[test]
    pub fn test_my_vrf() {
        let mut rng = test_rng();

        // generate public parameters
        // g, h
        let g1 = G1Affine::rand(&mut rng); //for pid_sender
        let g2 = G1Affine::rand(&mut rng); //for s_sender
        let g3 = G1Affine::rand(&mut rng); //for sn (of context credential)
        let g4 = G1Affine::rand(&mut rng); //for sn (of context credential)
        let g5 = G1Affine::rand(&mut rng); // for 1/s_sender + sn
        let g = G1Affine::rand(&mut rng); //for randomness

        let pid_sender = Fr::rand(&mut rng);
        let s_sender = Fr::rand(&mut rng);
        let sn = Fr::rand(&mut rng);
        let exponent_s_sn = s_sender + sn;
        let exponent_s_sn_inv = exponent_s_sn
            .inverse()
            .expect("exponent should be invertible");

        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);
        let r3 = Fr::rand(&mut rng);
        let r4 = Fr::rand(&mut rng);
        let r5 = -(r3 / exponent_s_sn);
        let r6 = Fr::rand(&mut rng);

        assert!(
            (r5 + (r3 * exponent_s_sn_inv)).is_zero(),
            "they shoudl cancel each other out"
        );

        // cm1 = g1^pid_sender + g2^s_sender + g^r1     - prove opening of cm1
        // cm2 = g1^pid_sender + g3^sn + g^r2           - prove opening of cm2
        // cm3 = g4^{s_sender + sn} + g^r3              - uses responses from cm1,cm2 to prove exponent is made from it's exponents
        // cm4 = g4^{1/s_sender + sn} + g^r4            - commits to the inverse exponent, can't prove anything with this yet
        // cm5 = cm3^{1/1/s_sender + sn}}  + g^r5       - (g4^{s_sender + sn} + g^r3)^{1/1/s_sender + sn}   =   g4 + g^{r3/s_sender + sn} + g^r5 where r5 = -{r3/(s_sender + sn)}
        // cm6 = g^r6
        let c = Fr::rand(&mut rng);

        let cm1 = g1.mul(pid_sender) + g2.mul(s_sender) + g.mul(r1);
        let cm2 = g1.mul(pid_sender) + g3.mul(sn) + g.mul(r2);
        let cm3 = g4.mul(exponent_s_sn) + g.mul(r3);
        let cm4 = g5.mul(exponent_s_sn_inv) + g.mul(r4);
        let cm5 = cm3.mul(exponent_s_sn_inv) + g.mul(r5);
        let cm6 = g.mul(r6);

        let a_pid_sender = Fr::rand(&mut rng);
        let a_s_sender = Fr::rand(&mut rng);
        let a_sn = Fr::rand(&mut rng);
        // let a_exponent_s_sn = Fr::rand(&mut rng);
        let a_exponent_s_sn_inv = Fr::rand(&mut rng);
        let a_r1 = Fr::rand(&mut rng);
        let a_r2 = Fr::rand(&mut rng);
        let a_r3 = Fr::rand(&mut rng);
        let a_r4 = Fr::rand(&mut rng);
        let a_r5 = Fr::rand(&mut rng);
        let a_r6 = Fr::rand(&mut rng);

        let T1 = g1.mul(a_pid_sender) + g2.mul(a_s_sender) + g.mul(a_r1);
        let T2 = g1.mul(a_pid_sender) + g3.mul(a_sn) + g.mul(a_r2);
        let T3 = g4.mul(a_s_sender + a_sn) + g.mul(a_r3);
        let T4 = g5.mul(a_exponent_s_sn_inv) + g.mul(a_r4);
        let T5 = cm3.mul(a_exponent_s_sn_inv) + g.mul(a_r5);
        let T6 = g.mul(a_r6);

        let z_pid_sender = a_pid_sender + c * pid_sender;
        let z_s_sender = a_s_sender + c * s_sender;
        let z_r1 = a_r1 + c * r1;

        let z_sn = a_sn + c * sn;
        let z_r2 = a_r2 + c * r2;

        let z_r3 = a_r3 + c * r3;

        let z_exponent_s_sn_inv = a_exponent_s_sn_inv + c * exponent_s_sn_inv;
        let z_r4 = a_r4 + c * r4;

        let z_r5 = a_r5 + c * r5;
        let z_r6 = a_r6 + c * r6;

        // cm1 * c + T1 = g1 * z_pid_sender + g2 * z_s_sender + g * z_r1
        let is_cm1_valid =
            cm1.mul(c) + T1 == g1.mul(z_pid_sender) + g2.mul(z_s_sender) + g.mul(z_r1);
        assert!(is_cm1_valid, "is_cm1_valid isn't valid");

        let is_cm2_valid = cm2.mul(c) + T2 == g1.mul(z_pid_sender) + g3.mul(z_sn) + g.mul(z_r2);
        assert!(is_cm2_valid, "cm2 isn't valid");

        let is_cm3_valid = cm3.mul(c) + T3 == g4.mul(z_s_sender + z_sn) + g.mul(z_r3);
        assert!(is_cm3_valid, "cm3 isn't valid");

        let is_cm4_valid = cm4.mul(c) + T4 == g5.mul(z_exponent_s_sn_inv) + g.mul(z_r4);
        assert!(is_cm4_valid, "cm4 isn't valid");

        let is_cm5_valid = cm5.mul(c) + T5 == cm3.mul(z_exponent_s_sn_inv) + g.mul(z_r5);
        assert!(is_cm5_valid, "cm5 isn't valid");

        let is_cm6_valid = cm6.mul(c) + T6 == g.mul(z_r6);
        assert!(is_cm6_valid, "cm6 isn't valid");

        // let cm4_inv = cm4.neg();

        assert_eq!(cm4.add(cm5.neg()), g);

        // let lhs = cm1.mul(c) + T1;
        // let rhs = g1.mul(z_pid_sender) + g2.mul(z_s_sender) + g.mul(z_r1);
        // assert_eq!(lhs, rhs, "defs not is_cm1_valid isn't valid");

        // let nullif =
    }
}
