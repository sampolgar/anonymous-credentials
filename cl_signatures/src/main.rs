// use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
// use ark_ff::{BigInteger, PrimeField};
// use ark_secp256k1::Fq;
// use ark_std::UniformRand;
// use rand::thread_rng;
// use sha2::Sha256;

// fn main() {
//     let mut rng = thread_rng();
//     let a: Fq = Fq::rand(&mut rng);
//     let hasher = <DefaultFieldHasher<Sha256> as HashToField<Fq>>::new(&[]);
//     let preimage = a.into_bigint().to_bytes_be();
//     let hashes: Vec<Fq> = hasher.hash_to_field(&preimage, 2);
//     println!("Hashes: {:?}", hashes);
// }

use crate::person::Person;
mod person;

fn main() {
    let me = Person {
        name: "Alice".to_string(),
    };
    println!("{:?}", me);
}