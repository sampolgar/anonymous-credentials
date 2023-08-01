//https://chat.openai.com/c/4e0859ce-ae16-41d4-a82f-4e3a9f6a151d
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{RngCore, OsRng};

fn main() {
    println!("Hello, world!");

    //Prover knows a secret 
    let secret = Scalar::random(&mut OsRng);

    // Prover knows a Witness
    let witness = Scalar::random(&mut OsRng);

    // Prover creates a commitment to the witness
    let commitment = witness * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    // Prover creates a proof of knowledge of the witness
    let mut transcript = Transcript::new(b"Schnorr Protocol");
    transcript.append_message(b"commitment", &commitment.compress().to_bytes());


    let challenge = transcript.challenge_scalar(b"challenge");

    let response = witness + challenge * secret;


    //Verify
    

}
