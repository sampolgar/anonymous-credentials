use num_bigint::BigUint;
use num_traits::pow::Pow;

/// run cargo test for below test cases
/// using prime number p = 2^256 - 2^32 - 977
/// Elliptic curve: y^2 = x^3 + 7
/// checking lhs == rhs for point (x, y)

pub fn is_secp256k1_point(x: BigUint, y: BigUint) -> bool {
    let p: BigUint = BigUint::from(2_u32).pow(256_u32)
        - BigUint::from(2_u32).pow(32_u32)
        - BigUint::from(977_u32);

    let lhs: BigUint = y.pow(2_u32) % &p;
    let rhs: BigUint = (x.pow(3_u32) + 7_u32) % p.clone();
    println!("{} == {}", lhs, rhs);
    return lhs == rhs;
}

// A = 2, B = 3
// A << 1
// TODO: implement this
pub fn is_secp256k1_point_bitshift(x: BigUint, y: BigUint) -> bool {
    let p: BigUint = BigUint::from(2_u32).pow(256_u32)
        - BigUint::from(2_u32).pow(32_u32)
        - BigUint::from(977_u32);

    let lhs: BigUint = y.pow(2_u32) % &p;
    let rhs: BigUint = (x.pow(3_u32) + 7_u32) % p.clone();
    println!("{} == {}", lhs, rhs);
    return lhs == rhs;
}
