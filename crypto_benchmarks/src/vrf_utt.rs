use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use ark_std::test_rng;
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
        // bases.push(self.g3);
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
    use ark_bls12_381::{Bls12_381, Fr};
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
}
