use num_bigint::BigUint;
use num_traits::pow::Pow;

/// run cargo test for below test cases
/// using prime number p = 2^256 - 2^32 - 977
/// Elliptic curve: y^2 = x^3 + 7
/// checking lhs == rhs for point (x, y)

fn is_secp256k1_point(x: BigUint, y: BigUint) -> bool {
    let p: BigUint = BigUint::from(2_u32).pow(256_u32)
        - BigUint::from(2_u32).pow(32_u32)
        - BigUint::from(977_u32);

    let lhs: BigUint = y.pow(2_u32) % &p;
    let rhs: BigUint = (x.pow(3_u32) + 7_u32) % p.clone();
    println!("{} == {}", lhs, rhs);
    return lhs == rhs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_valid_point() {
        let x: BigUint =
            "55066263022277343669578718895168534326250603453777594175500187360389116729240"
                .parse()
                .unwrap();
        let y: BigUint =
            "32670510020758816978083085130507043184471273380659243275938904335757337482424"
                .parse()
                .unwrap();
        assert_eq!(is_secp256k1_point(x, y), true);
    }

    #[test]
    fn test_invalid_point() {
        // Some arbitrary numbers that don't lie on the curve
        let x = "48439561293906451759052585252797914202762949526041747995844080717082404635286"
            .parse()
            .unwrap();
        let y = "36134250956749795798585127919587881956611106672985015071877198253568414405109"
            .parse()
            .unwrap();
        assert_eq!(is_secp256k1_point(x, y), false);
    }

    #[test]
    fn test_invalid_point_again() {
        // Some arbitrary numbers that don't lie on the curve
        let x = "1234567890123456789012345678901234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let y = "9876543210987654321098765432109876543210987654321098765432109876543210"
            .parse()
            .unwrap();
        assert_eq!(is_secp256k1_point(x, y), false);
    }

    #[test]
    fn test_zero_point() {
        // Both x and y are zero
        let x = BigUint::from(0_u32);
        let y = BigUint::from(0_u32);
        assert_eq!(is_secp256k1_point(x, y), false);
    }
}

// TODO change power functions to bit shift functions
