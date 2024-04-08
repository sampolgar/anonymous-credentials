use ark_bls12_381::Fq as F;
use ark_ff::{BigInteger, Field, FpConfig, PrimeField, Zero};
use ark_std::{One, UniformRand};
use num_bigint::BigUint;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field() {
        let mut rng = ark_std::test_rng();
        let a = F::rand(&mut rng);

        // access modulus
        let modulus = <F as PrimeField>::MODULUS;
        println!("Modulus: {:?}", modulus);
        println!("a: {:?}", a);
        assert_eq!(a.pow(modulus), a);

        // convert field elements to integers
        let one: num_bigint::BigUint = F::one().into();
        assert_eq!(one, num_bigint::BigUint::one());
        println!("one: {:?}", one);

        // construct Fq from arbitrary bytes
        let n = F::from_le_bytes_mod_order(&modulus.to_bytes_le());
        println!("n: {:?}", n);
        assert_eq!(n, F::zero());
    }
}
