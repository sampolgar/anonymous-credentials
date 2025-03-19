use crate::commitment::{Commitment, CommitmentKey};
use crate::credential::ShowCredential;
use crate::credential::{self, Credential};
use crate::error::Error;
use crate::proof::CommitmentProof;
use crate::public_params::PublicParams;
use crate::signature::{generate_keys, SecretKey, Signature, VerificationKey};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};
use thiserror::Error;
// We can speedup multi credential verification by batching the signature pairings into a pairing checker.
// Then implement the schnorr efficiency improvement from the threshold variant I made

// main protocol struct
pub struct MimcAbc<E: Pairing> {
    pub pp: PublicParams<E>,
    pub ck: CommitmentKey<E>,
}

impl<E: Pairing> MimcAbc<E> {
    // Initialize with existing parameters
    pub fn new(pp: PublicParams<E>) -> Self {
        let ck = CommitmentKey {
            ck: pp.ck.clone(),
            ck_tilde: pp.ck_tilde.clone(),
        };
        Self { pp, ck }
    }

    // Generate fresh parameters and keys
    pub fn setup(n: usize, rng: &mut impl Rng) -> (Self, SecretKey<E>, VerificationKey<E>) {
        let pp = PublicParams::<E>::new(&n, rng);
        let protocol = Self::new(pp);
        let (sk, vk) = generate_keys(&protocol.pp, rng);
        (protocol, sk, vk)
    }

    pub fn obtain(&self, credential: &Credential<E>, rng: &mut impl Rng) -> CommitmentProof<E> {
        credential.prove_commitment(&self.pp, rng)
    }

    // Issuer issues a signature
    pub fn issue(
        &self,
        proof: &CommitmentProof<E>,
        sk: &SecretKey<E>,
        rng: &mut impl Rng,
    ) -> Result<Signature<E>, Error> {
        if !proof.verify() {
            return Err(Error::InvalidProof);
        }
        Ok(sk.sign(&proof.commitment, &self.pp, rng))
    }

    pub fn show(&self, credential: &Credential<E>, rng: &mut impl Rng) -> ShowCredential<E> {
        let delta_r = E::ScalarField::rand(rng);
        let delta_u = E::ScalarField::rand(rng);
        credential.show(&self.pp, &delta_r, &delta_u, rng)
    }

    // Verifier checks a credential
    pub fn verify(&self, show_cred: ShowCredential<E>, vk: &VerificationKey<E>) -> bool {
        show_cred.verify(&self.pp, vk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::Credential;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;

    #[test]
    fn test_mimc_abc_credential_lifecycle() {
        // Setup protocol with parameters and keys
        let mut rng = ark_std::test_rng();
        let n = 4; // Number of attributes
        let (protocol, issuer_sk, issuer_vk) = MimcAbc::<Bls12_381>::setup(n, &mut rng);

        // Create user attributes with ID as first attribute
        let user_id = Fr::rand(&mut rng);
        let attributes: Vec<Fr> = (0..n - 1).map(|_| Fr::rand(&mut rng)).collect();
        let mut attributes_with_id = vec![user_id];
        attributes_with_id.extend(attributes);
        println!("Attributes: {:?}", attributes_with_id.len());

        // Create credential
        let r = Fr::rand(&mut rng);
        let mut credential = Credential::new(&protocol.ck, &protocol.pp, &attributes_with_id, r);

        // User creates proof for credential
        let proof = protocol.obtain(&credential, &mut rng);

        // Issuer issues signature
        let signature = protocol
            .issue(&proof, &issuer_sk, &mut rng)
            .expect("Issuance failed");

        // Add signature to credential
        credential.add_signature(signature);

        // Verify the original credential
        assert!(
            credential.verify(&protocol.pp, &issuer_vk),
            "Original credential verification failed"
        );

        // User shows credential
        let presentation = protocol.show(&credential, &mut rng);

        // Verifier checks presentation
        assert!(
            protocol.verify(presentation, &issuer_vk),
            "Credential presentation verification failed"
        );
    }
}
