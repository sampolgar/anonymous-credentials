use super::hash::HashUtil;
use super::pedersen::PedersenCommitment;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::Rng, One, UniformRand};
use std::ops::{Add, Mul};

pub struct SecretKey<G: AffineRepr> {
    x1: G,
}

pub struct PublicKey<G: AffineRepr> {
    y1: G,
    x2: G,
    y2: G,
}

pub struct Signature<G: AffineRepr> {
    sigma_1: G,
    sigma_2: G,
}

pub fn generate_keys<G: AffineRepr, R: Rng>(rng: &mut R) -> (SecretKey<G>, PublicKey<G>) {
    let x = G::ScalarField::rand(rng);
    let y = G::ScalarField::rand(rng);

    let sk = SecretKey {
        x1: G::generator().mul(x).into_affine(),
    };

    let pk = PublicKey {
        y1: G::generator().mul(y).into_affine(),
        x2: G::generator().mul(x).into_affine(),
        y2: G::generator().mul(y).into_affine(),
    };

    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_std::rand::RngCore;

    #[test]
    fn test_generate_keys() {
        let mut rng = ark_std::test_rng();
        let (sk, pk) = generate_keys::<G1Affine, _>(&mut rng);
        assert_ne!(sk.x1, G1Affine::identity());
        assert_ne!(pk.y1, G1Affine::identity());
        assert_ne!(pk.x2, G1Affine::identity());
        assert_ne!(pk.y2, G1Affine::identity());
    }

    #[test]
    fn test_ps() {
        let g1 = G1Affine::generator();
        let mut rng = ark_std::test_rng();
        let (sk, pk) = generate_keys::<G1Affine, _>(&mut rng);

        // C = g^r y1^m
        let m_string = b"secret message";
        // let message_as_fp = HashUtil::hash_to_field(message.as_bytes());
        let m = HashUtil::<Fr, G1Affine>::hash_to_field(m_string);
        let t = Fr::rand(&mut rng);

        let commitment = PedersenCommitment::<G1Affine>::new(G1Affine::generator(), pk.y1);
        let c = commitment.commit(&t, &m);

        // prove knowledge of the opening of c
        let m_prime = Fr::rand(&mut rng);
        let t_prime = Fr::rand(&mut rng);
        let commitment_prime = PedersenCommitment::<G1Affine>::new(G1Affine::generator(), pk.y1);
        let c_prime = commitment_prime.commit(&t_prime, &m_prime);

        let e = HashUtil::hash_groups_to_field(&[c, c_prime]);

        // c = g^t y1^m
        let z1 = t_prime + e * t;
        let z2 = m_prime + e * m;

        // verifier verifies
        let bool = g1.mul(z1) + pk.y1.mul(z2) == c_prime + c.mul(e);
        print!("{:?}", bool);
        assert!(bool);

        // if true, signer signs
        let u = Fr::rand(&mut rng);
        let sigma_1 = g1.mul(u).into_affine();
        let sigma_2 = pk.y1.mul(u).into_affine();
        let signature = Signature {
            sigma_1: sigma_1,
            sigma_2: sigma_2,
        };
    }
}
