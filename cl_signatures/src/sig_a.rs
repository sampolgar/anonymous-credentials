use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ark_std::{One, UniformRand, Zero};

use ark_bls12_381::{
    fq::Fq, fq2::Fq2, Bls12_381, Fq12, Fr as ScalarField, G1Affine as G1a, G1Projective as G1p,
    G2Affine as G2a, G2Projective as G2p,
};

pub fn key_gen() -> (G1p, G2p, G1p, G2p) {
    let mut rng = ark_std::test_rng();
    let x = ScalarField::rand(&mut rng);
    let y = ScalarField::rand(&mut rng);

    let g1a = G1a::generator();
    let g2a = G2a::generator();

    // affine scalar mul is more efficient https://github.com/arkworks-rs/algebra/tree/master/ec
    let x1 = g1a * x;
    let x2 = g2a * x;
    let y1 = g1a * y;
    let y2 = g2a * y;

    (x1, x2, y1, y2)
}

pub fn sign() {
    
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen() {
        key_gen();
    }
}

// // sign
// // input m, sk, pk
// // chose random a
// // sigma (a,b,c) = (a*G1 + b*G2, )

// // verify
// // e(a,Y) = e(g,b)
// // e(X,a) . e(X,b^m) = e(g,c)

// //pos2 is G2
// // X = G1, Y = G2
// // a = G1, b = G2

// // a = G2, b = G2, c = G2
