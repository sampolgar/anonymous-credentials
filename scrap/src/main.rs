// (Long Division Algorithm). Using the programming language of your choice, write an algorithm that computes integer long division and handles all edge cases properly.
// Edge Cases
// if divisor = 0, return divide by zero error
// if dividend = 0, return (0, 0)
// if |dividend| < |divisor|, return dividend (because you can't divide by a bigger number w integer (0, dividend)
// if divisor & dividend are both positive, return (m, r)
// if dividend is negative, and divisor is positive, return (-m, r)
// if a is positive and b is negative, calculate m+1 and r
// if both are negative, ??

// fn main() {

// }

// def GCD(a, b):
//     if a == 0:
//         return b

//     return GCD(b%a, a)

// print("GCD(25,10)=", GCD(25,10))
// print("GCD(63,57)=", GCD(63,57))
// print("GCD(7,9)=", GCD(7,9))
// print("GCD(4,14)=", GCD(4,16))

// fn main() {
//     println!("{:?} ---- ", euclidean_algo(63, 57));
//     println!("{:?} ---- ", euclidean_algo(4, 16));
//     println!("{:?} ---- ", euclidean_algo(16, 4));
//     println!("{:?} ---- ", euclidean_algo(7, 9));
// }

fn euclidean_algo(mut a: i32, mut b: i32) -> (i32) {
    if a < b {
        std::mem::swap(&mut a, &mut b);
    }
    if b == 0 {
        return (a);
    }
    println!("b{} % a{} = bmoda{}", b, a, b % a);
    return euclidean_algo(b, a % b);
}

fn long_division(dividend: i32, divisor: i32) -> (i32, i32) {
    // println!("{:?}", long_division(27, 5)); // (5, 2)
    // println!("{:?}", long_division(-27, 5)); // (-6, 3)
    // println!("{:?}", long_division(-1687, 11)); // (-154, 7)
    // println!("{:?}", long_division(127, 0)); // (0, 0)
    // println!("{:?}", long_division(0, 127)); // (0, 0)
    // println!("{:?}", long_division(27, -5)); // (-5, 2)
    if divisor == 0 {
        panic!("Divide by zero error");
    } else if dividend == 0 {
        return (0, 0);
    } else if dividend.abs() < divisor.abs() {
        return (0, dividend);
    }

    // create a sign variable to keep track of the sign of the quotient
    let sign_divisor = if divisor < 0 { -1 } else { 1 };

    // calculate the quotient and remainder w relevent signs
    let mut quotient = dividend / divisor;
    let mut remainder = dividend % divisor;

    if (dividend < 0) != (divisor < 0) && remainder != 0 {
        remainder += divisor;
        quotient -= 1;
    }

    //remainder must be bigger or equal to 0
    println!("{} * {} + {} = {}", quotient, divisor, remainder, dividend);
    assert!(remainder >= 0);
    // quotient * divisor + remainder = dividend
    assert_eq!(quotient * divisor.abs() + remainder, dividend);
    return (quotient, remainder);
}

// fn main() {
//     let n = 630;
//     let binary_representation = int_to_binary(n);
//     println!("The binary representation of {} is {}", n, binary_representation);
// }

fn int_to_binary(mut n: u32) -> String {
    if n == 0 {
        return "0".to_string();
    }

    let mut binary_representation = String::new();

    while n > 0 {
        let remainder = n % 2;
        println!("{} % 2 = {}", n, remainder);
        binary_representation.insert(0, char::from_digit(remainder, 10).unwrap());
        n = n / 2;
        println!("{} ", n);
    }

    binary_representation
}

// fn extended_euclidean_algo()

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