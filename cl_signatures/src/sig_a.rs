use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ark_std::{One, UniformRand, Zero};

use ark_bls12_381::{
    fq::Fq, fq2::Fq2, Bls12_381, Fq12, Fr as ScalarField, G1Affine as G1a, G1Projective as G1p,
    G2Affine as G2a, G2Projective as G2p,
};

pub struct Sk {
    x: ScalarField,
    y: ScalarField,
}

pub struct Pk {
    x1: G1p,
    y1: G1p,
}

pub fn key_gen() -> (Sk, Pk) {
    let mut rng = ark_std::test_rng();
    let x = ScalarField::rand(&mut rng);
    let y = ScalarField::rand(&mut rng);

    let g1a = G1a::generator();

    // affine scalar mul is more efficient https://github.com/arkworks-rs/algebra/tree/master/ec
    let x1 = g1a * x;
    let y1 = g1a * y;
    let sk = Sk { x, y };
    let pk = Pk { x1, y1 };
    (sk, pk)
}

pub fn sign() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen() {
        key_gen();
        // gen random a
        // gen message m
    }
}

// sign (m, sk, pk)
// a <- Zq
// sigma (a,b,c) = (a, a^y, a^{x+mxy})

// verify
// e(a1,y2) = e(g1,b2)
// e(x1,a2) . e(x1,b2^m) = e(g1,c2)

// a1, b2, y2
// x1, a2, b2, c2

// //pos2 is G2
// // X = G1, Y = G2
// // a = G1, b = G2

// // a = G2, b = G2, c = G2
