// extern crate rand;
// extern crate ed25519_dalek;

// use rand::rngs::OsRng;
// use ed25519_dalek::Keypair;
// use ed25519_dalek::Signature;
// // {Keypair, Signature};

// let mut csprng = OsRng{};
// let keypair: Keypair = Keypair::generate(&mut csprng);

// use ed25519_dalek::{Signature, Signer};
// let message: &[u8] = b"This is a test of the tsunami alert system.";
// let signature: Signature = keypair.sign(message);

// use ed25519_dalek::Verifier;
// assert!(keypair.verify(message, &signature).is_ok());



// fn main() {
//     let mut csprng = OsRng{};
//     let keypair: Keypair = Keypair::generate(&mut csprng);
//     let message: &[u8] = b"Hello, World!";
//     let signature: Signature = keypair.sign(message);
//     assert!(keypair.verify(message, &signature).is_ok());
// }

// use fastcrypto::secp256k1;
// use fastcrypto::{traits::{KeyPair, Signer, VerifyingKey}};
// use rand::thread_rng;

// fn main() 

// let kp = Secp256k1KeyPair::generate(&mut thread_rng());
// let message: &[u8] = b"Hello, world!";
// let signature = kp.sign(message);
// assert!(kp.public().verify(message, &signature).is_ok());