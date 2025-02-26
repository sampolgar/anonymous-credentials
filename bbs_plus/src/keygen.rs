use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

pub struct SecretKey<E: Pairing> {
    pub x: E::ScalarField,
}

pub struct PublicKey<E: Pairing> {
    pub w: E::G2Affine,
    pub h0: E::G1Affine,
    pub h1hL: Vec<E::G1Affine>,
}

pub fn gen_keys<E: Pairing>(
    pp: &PublicParams<E>,
    rng: &mut impl Rng,
) -> (SecretKey<E>, PublicKey<E>) {
    let x = E::ScalarField::rand(rng);
    let w = pp.g2.mul(x).into_affine();
    let h0 = E::G1Affine::rand(rng);
    let h1hL = (0..pp.L)
        .map(|_| E::G1Affine::rand(rng))
        .collect::<Vec<_>>();
    let sk = SecretKey { x };
    let pk = PublicKey { w, h0, h1hL };
    (sk, pk)
}

// impl<E: Pairing> PublicKey<E> {
//     pub fn get_h0(&self) -> E::G1Affine {
//         let h0 = self.hig1[0];
//         h0
//     }

//     pub fn get_h1_to_hL(&self) -> Vec<E::G1Affine> {
//         let mut points = self.hig1.clone();
//         points.split_off(1)
//     }
// }
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_keygen() {
        let L = 4;
        let mut rng = test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&L, &context, &mut rng);

        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Check that the secret key and public key are generated correctly
        assert!(sk.x != Fr::zero(), "Secret key should not be zero");
        assert!(pk.w != pp.g2, "Public key w should not be equal to g2");
        assert_eq!(
            pk.h1hL.len(),
            (L) as usize,
            "Public key hig1 should have L + 1 elements"
        );
    }
}
