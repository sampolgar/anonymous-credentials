use ark_bls12_381::{Fr as ScalarField, G1Affine as Gaff, G1Projective as Gpro};
use ark_ec::VariableBaseMSM;
use ark_ff::{Field, PrimeField};
use ark_std::{ops::Mul, UniformRand, Zero};

#[cfg(test)]
mod tests {
    use ark_ec::short_weierstrass::Projective;

    use super::*;

    #[test]
    fn test_group() {
        let mut rng = ark_std::test_rng();
        let a = Gpro::rand(&mut rng);
        let b = Gpro::rand(&mut rng);
        println!("{:?}, {:?}", a, b);
        let c = a + b;
        println!("{:?}", c);

        let d = a - b;
        println!("{:?}", d);

        // negate elements
        let e = -a;
        assert_eq!(e + a, Gpro::zero());

        // scalar mul
        let scalar = ScalarField::rand(&mut rng);
        let e = c.mul(scalar);
        let f = e.mul(scalar.inverse().unwrap());
        assert_eq!(f, c);
    }

    #[test]
    // more efficient scalar mul - use Affine coordinates (simple integer representation [123,123]
    // changes into projective for output?
    // VariableBaseMSM computes inner product between vector of scalars s and vector of group elements g
    // s.iter().zip(g).map(|(s,g)| g * s).sum()
    fn test_ec_mul() {
        let mut rng = ark_std::test_rng();
        let a = Gaff::rand(&mut rng);
        let b = Gaff::rand(&mut rng);
        let z = Gpro::rand(&mut rng);

        println!("Affine representation: {:?}", a);
        println!("Projective representation: {:?}", z);
        let s1 = ScalarField::rand(&mut rng);
        let s2 = ScalarField::rand(&mut rng);

        let r = Gpro::msm(&[a, b], &[s1, s2]).unwrap();
        assert_eq!(r, a * s1 + b * s2);
    }
}
