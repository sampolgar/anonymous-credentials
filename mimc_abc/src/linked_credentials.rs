use crate::commitment::Commitment;
use crate::credential::{Credential, ShowCredential};
use crate::error::Error;
use crate::identity_binding::{IdentityBinding, IdentityBindingProof};
use crate::public_params::PublicParams;
use crate::signature::VerificationKey;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

/// Represents multiple credentials shown together with proof that they share the same identity
pub struct LinkedCredentialPresentation<E: Pairing> {
    pub credential_presentations: Vec<ShowCredential<E>>, // Individual presentations of each credential
    pub identity_proof: IdentityBindingProof<E>, // Proof that all credentials share the same identity
}

impl<E: Pairing> LinkedCredentialPresentation<E> {
    /// Create a linked presentation from multiple credentials
    pub fn create(
        credentials: &[&Credential<E>],
        public_params: &[&PublicParams<E>],
        rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        if credentials.is_empty() {
            return Err(Error::Other("No credentials provided".to_string()));
        }

        // First, create individual credential presentations with randomization
        let mut credential_presentations = Vec::with_capacity(credentials.len());
        let mut randomized_commitments = Vec::with_capacity(credentials.len());
        let mut messages = Vec::with_capacity(credentials.len());
        let mut randomness = Vec::with_capacity(credentials.len());

        for (i, credential) in credentials.iter().enumerate() {
            // Generate randomization factors
            let delta_r = E::ScalarField::rand(rng);
            let delta_u = E::ScalarField::rand(rng);

            // Show the credential (creating randomized presentation)
            let presentation = credential.show(public_params[i], &delta_r, &delta_u, rng);

            // Store the randomized values for the identity binding proof
            randomized_commitments.push(presentation.randomized_commitment.clone());
            messages.push(credential.get_messages().clone());
            randomness.push(presentation.r_new);

            credential_presentations.push(presentation);
        }

        // Create the identity binding proof using the randomized commitments
        let identity_proof = IdentityBinding::prove(
            &randomized_commitments,
            &messages,
            &randomness,
            public_params,
            rng,
        )?;

        Ok(LinkedCredentialPresentation {
            credential_presentations,
            identity_proof,
        })
    }

    /// Verify a linked credential presentation
    pub fn verify(
        &self,
        public_params: &[&PublicParams<E>],
        verification_keys: &[&VerificationKey<E>],
    ) -> Result<bool, Error> {
        // Verify the identity binding proof
        if !IdentityBinding::verify(&self.identity_proof, public_params)? {
            return Ok(false);
        }

        // Verify each individual credential presentation
        for (i, presentation) in self.credential_presentations.iter().enumerate() {
            if !presentation.verify(public_params[i], verification_keys[i]) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MimcAbc;
    use crate::signature::{SecretKey, Signature};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_linked_credential_presentation() {
        let mut rng = test_rng();

        // Setup protocols and keys for multiple issuers
        let n = 5; // attributes per credential
        let (protocol1, sk1, vk1) = MimcAbc::<Bls12_381>::setup(n, &mut rng);
        let (protocol2, sk2, vk2) = MimcAbc::<Bls12_381>::setup(n, &mut rng);

        // Create a common user identity
        let user_id = Fr::rand(&mut rng);

        // Create credentials with the same identity
        let mut messages1 = vec![user_id];
        let mut messages2 = vec![user_id];

        // Add random attributes
        for _ in 1..n {
            messages1.push(Fr::rand(&mut rng));
            messages2.push(Fr::rand(&mut rng));
        }

        // Create commitments and credentials
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);

        let mut credential1 = Credential::new(&protocol1.ck, &protocol1.pp, &messages1, r1);

        let mut credential2 = Credential::new(&protocol2.ck, &protocol2.pp, &messages2, r2);

        // Issue signatures on the credentials
        let proof1 = credential1.prove_commitment(&protocol1.pp, &mut rng);
        let proof2 = credential2.prove_commitment(&protocol2.pp, &mut rng);

        let signature1 = protocol1
            .issue(&proof1, &sk1, &mut rng)
            .expect("Issuance failed");
        let signature2 = protocol2
            .issue(&proof2, &sk2, &mut rng)
            .expect("Issuance failed");

        credential1.add_signature(signature1);
        credential2.add_signature(signature2);

        // Create linked presentation
        let linked_presentation = LinkedCredentialPresentation::create(
            &[&credential1, &credential2],
            &[&protocol1.pp, &protocol2.pp],
            &mut rng,
        )
        .expect("Linked presentation creation failed");

        // Verify the linked presentation
        let is_valid = linked_presentation
            .verify(&[&protocol1.pp, &protocol2.pp], &[&vk1, &vk2])
            .expect("Verification failed");

        assert!(is_valid, "Linked credential presentation should verify");

        // Test negative case: different user identities (this should be caught in create())
        let different_id = Fr::rand(&mut rng);
        let mut messages3 = vec![different_id]; // Different ID
        for _ in 1..n {
            messages3.push(Fr::rand(&mut rng));
        }

        let r3 = Fr::rand(&mut rng);
        let mut credential3 = Credential::new(&protocol1.ck, &protocol1.pp, &messages3, r3);

        let proof3 = credential3.prove_commitment(&protocol1.pp, &mut rng);
        let signature3 = protocol1
            .issue(&proof3, &sk1, &mut rng)
            .expect("Issuance failed");
        credential3.add_signature(signature3);

        // This should fail during creation
        let invalid_presentation = LinkedCredentialPresentation::create(
            &[&credential1, &credential3],
            &[&protocol1.pp, &protocol1.pp],
            &mut rng,
        );

        assert!(
            invalid_presentation.is_err(),
            "Creating linked presentation with different IDs should fail"
        );
    }
}
