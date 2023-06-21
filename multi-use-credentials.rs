extern crate ring;
extern crate rand;

use ring::{rand, signature};
use ring::signature::RsaKeyPair;
use ring::rand::SystemRandom;

// generate function takes in random number and bit size
// returns an RSAKeyPair. ? returns early if error
// Ok returns a key pair when successful

fn keygen() -> Result<RsaKeyPair, ring::error::Unspecified> {
    let rng = SystemRandom::new();

    // Generate a new 2048-bit RSA key pair
    let key_pair = RsaKeyPair::generate(&rng, 2048)?;

    Ok(key_pair) 
}

fn main() {
    match keygen() {
        Ok(key_pair) => println!("Generated a key pair."),
        Err(e) => println!("Failed to generate a key pair."),
    }
}
`