use curve_point_test::{is_secp256k1_point, is_secp256k1_point_bitshift};
mod tests {
    use super::*;
    use crate::points::{invalid_point, invalid_point_2, valid_point, zero_point};
    /// test cases for non-bit shift
    #[test]
    fn test_valid_point() {
        let (x, y) = valid_point();
        assert_eq!(is_secp256k1_point(x, y), true);
    }

    #[test]
    fn test_invalid_point() {
        let (x, y) = invalid_point();
        assert_eq!(is_secp256k1_point(x, y), false);
    }

    #[test]
    fn test_valid_point_2() {
        let (x, y) = invalid_point_2();
        assert_eq!(is_secp256k1_point(x, y), false);
    }

    #[test]
    fn test_zero_point() {
        let (x, y) = zero_point();
        assert_eq!(is_secp256k1_point(x, y), false);
    }

    /// test cases for bit shift
    #[test]
    fn test_valid_point_bitshift() {
        let (x, y) = valid_point();
        assert_eq!(is_secp256k1_point_bitshift(x, y), true);
    }

    #[test]
    fn test_invalid_point_bitshift() {
        let (x, y) = invalid_point();
        assert_eq!(is_secp256k1_point_bitshift(x, y), false);
    }

    #[test]
    fn test_valid_point_2_bitshift() {
        let (x, y) = invalid_point_2();
        assert_eq!(is_secp256k1_point_bitshift(x, y), false);
    }

    #[test]
    fn test_zero_point_bitshift() {
        let (x, y) = zero_point();
        assert_eq!(is_secp256k1_point_bitshift(x, y), false);
    }
}

mod points {
    use num_bigint::BigUint;
    pub fn valid_point() -> (BigUint, BigUint) {
        let x: BigUint =
            "55066263022277343669578718895168534326250603453777594175500187360389116729240"
                .parse()
                .unwrap();
        let y: BigUint =
            "32670510020758816978083085130507043184471273380659243275938904335757337482424"
                .parse()
                .unwrap();
        return (x, y);
    }

    pub fn invalid_point() -> (BigUint, BigUint) {
        // Some arbitrary numbers that don't lie on the curve
        let x = "48439561293906451759052585252797914202762949526041747995844080717082404635286"
            .parse()
            .unwrap();
        let y = "36134250956749795798585127919587881956611106672985015071877198253568414405109"
            .parse()
            .unwrap();
        return (x, y);
    }

    pub fn invalid_point_2() -> (BigUint, BigUint) {
        // Some arbitrary numbers that don't lie on the curve
        let x = "1234567890123456789012345678901234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let y = "9876543210987654321098765432109876543210987654321098765432109876543210"
            .parse()
            .unwrap();
        return (x, y);
    }

    pub fn zero_point() -> (BigUint, BigUint) {
        // Both x and y are zero
        let x = BigUint::from(0_u32);
        let y = BigUint::from(0_u32);
        return (x, y);
    }
}
