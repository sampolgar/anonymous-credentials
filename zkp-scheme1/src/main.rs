//https://chat.openai.com/c/4e0859ce-ae16-41d4-a82f-4e3a9f6a151d
//https://ristretto.group/details/curve_models.html
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{RngCore, OsRng};


trait TranscriptProtocol {
    fn domain_sep(&mut self);
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self) {
        // A proof-specific domain separation label that should
    // uniquely identify the proof statement.
        self.append_bytes(b"dom-sep", b"TranscriptProtocol Example");
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_bytes(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        // Reduce a double-width scalar to ensure a uniform distribution
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

fn main() {
    println!("Hello, world!");

    // //Prover knows a secret 
    // let secret = Scalar::random(&mut OsRng);

    // // Prover knows a Witness
    // let witness = Scalar::random(&mut OsRng);

    // // Prover creates a commitment to the witness
    // let commitment = witness * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    // // Prover creates a proof of knowledge of the witness
    // let mut transcript = Transcript::new(b"Schnorr Protocol");
    // transcript.append_message(b"commitment", &commitment.compress().to_bytes());


    // let challenge = transcript.challenge_scalar(b"challenge");

    // let response = witness + challenge * secret;


    // //Verify
    
    // let mut verifier_transcript = Transcript::new(b"Schnorr Protocol");
    // verifier_transcript.append_message(b"commitment", &commitment.compress().to_bytes());
    // let verifier_challenge = verifier_transcript.challenge_scalar(b"challenge");



}
