use ark_bls12_381::Fr as ScalarField;
use ark_ff::PrimeField;
use blake2::{Blake2b512, Digest};

pub fn string_to_scalar(s: &str) -> ScalarField {
    let mut hasher = Blake2b512::new();
    hasher.update(s);
    let res = hasher.finalize();
    ScalarField::from_le_bytes_mod_order(&res[..])
}

#[cfg(test)]
mod tests {
    use super::string_to_scalar;
    use ark_bls12_381::Fr as ScalarField;

    #[test]
    fn test_string_to_scalar() {
        let s = "hello world";
        let result: ScalarField = string_to_scalar(s);
        println!("{:?}", result);
    }
}
