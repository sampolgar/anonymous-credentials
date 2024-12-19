// setup
// keygen

// Master
// obtain, issue
// show, verify

// Context
// obtain, issue
// show, verify

// sybil resistance
// User encrypts their
// or accountability, user escrows
// their PRF key by computing ciphertext escrow ← tpkeencapk(s) and generates a zero-knowledge
// proof π demonstrating 1) knowledge of the PRF key s in escrow ciphertext, 2) s knowledge of the
// same s within the commitment rcm, and 3) s in 1) and 2) are equal, ensuring the escrowed key
// matches the key in the credential

// user generates master credential
// user geneerates context credential

// let mastermessages = [s, ......]
// let contextmessages = [s,......]

// give proof system commitments from 2 different credentials
// cred.sig.rerandomize (rerandomizes credential and signature)
// cred.
// verify each
// verify proof of opening
// generate some other proof....

use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use ps_utt::commitment::{self, Commitment};
use ps_utt::credential::Credential;
use ps_utt::keygen::KeyPair;
use ps_utt::proofsystem::{CommitmentEqualityProof, CommitmentProof, CommitmentProofs};
use ps_utt::publicparams::PublicParams;
use ps_utt::signature::PSSignature;

pub struct SingleIssuerProtocol;

impl SingleIssuerProtocol {
    pub fn obtain<E: Pairing>(
        pp: &PublicParams<E>,
        messages: &Vec<E::ScalarField>,
    ) -> (Commitment<E>, Vec<u8>) {
        // Commits to messages
        // creates zkp of opening
        let mut rng = ark_std::rand::thread_rng();
        let r = E::ScalarField::rand(&mut rng);
        let com = Commitment::new(pp, messages, &r);
        let proof = CommitmentProofs::prove_knowledge(&com).unwrap();
        assert!(CommitmentProofs::verify_knowledge::<E>(&proof).unwrap());
        (com, proof)
    }

    pub fn issue<E: Pairing>(
        keypair: &KeyPair<E>,
        com: Commitment<E>,
        proof: Vec<u8>,
    ) -> Credential<E> {
        // issuer verifiers proof of opening
        // TODO check the context is OK s.t. ctx in keypair = ctx in pp = ctx in commitment
        // signs over commitment
        // returns credential
        // First verify the proof of knowledge
        assert!(CommitmentProofs::verify_knowledge::<E>(&proof).unwrap());

        // Sign the commitment
        let mut rng = ark_std::rand::thread_rng();
        let signature = PSSignature::sign(&com.pp, &keypair, &com, &mut rng);
        let context = com.pp.context;
        // Create and return credential
        Credential {
            commitment: com,
            signature,
            context,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};

    #[test]
    fn test_one_cred() {
        let mut rng = ark_std::rand::thread_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&6, &context, &mut rng);
        let keypair = KeyPair::<Bls12_381>::new(&pp, &mut rng);

        let secret = Fr::rand(&mut rng);
        let mut messages = vec![secret, context];
        messages.extend((0..4).map(|_| Fr::rand(&mut rng)));
        let (com, proof) = SingleIssuerProtocol::obtain(&pp, &messages);

        // Issuer creates credential
        let credential = SingleIssuerProtocol::issue(&keypair, com, proof);

        // Verify credential
        assert!(credential
            .signature
            .verify(&pp, &keypair, &credential.commitment));
    }
}

// assert_eq!(commitment.verify_opening(&messages, &r), true);
// (assuming you have a verify_opening method)
