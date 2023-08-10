use num_bigint::BigUint;
use num_traits::pow::Pow;

fn main() {
    let x1: BigUint =
        "55066263022277343669578718895168534326250603453777594175500187360389116729240"
            .parse()
            .unwrap();
    let y1: BigUint =
        "32670510020758816978083085130507043184471273380659243275938904335757337482424"
            .parse()
            .unwrap();

    let result = is_secp256k1_point(x1, y1);
    println!("Is it a valid point? {}", result);
}

fn is_secp256k1_point(x: BigUint, y: BigUint) -> bool {
    let p: BigUint = BigUint::from(2_u32).pow(256_u32)
        - BigUint::from(2_u32).pow(32_u32)
        - BigUint::from(977_u32);

    let lhs: BigUint = y.pow(2_u32) % &p;
    let rhs: BigUint = (x.pow(3_u32) + 7_u32) % p.clone();
    println!("{} == {}", lhs, rhs);
    return lhs == rhs;
}

// More concise than 2_i32.pow(256)
//y² mod p = (x³ + ax + b) mod p     let a = 0; let b = 7;
// BigUint::one() takes the value 1 and converts it to a BigUint.
// BigUint::one() << 256 .Then we shift it left 256 times, which is the same as multiplying by 2^256.
