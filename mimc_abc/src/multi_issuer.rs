// mimc_abc/src/multi_issuer.rs
use crate::commitment::CommitmentKey;
use crate::credential::{Credential, ShowCredential};
use crate::error::Error;
use crate::protocol::MimcAbc;
use crate::public_params::PublicParams;
use crate::signature::{SecretKey, VerificationKey};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use std::collections::HashMap;

/// Structure to represent an issuer in the system
pub struct Issuer<E: Pairing> {
    pub id: usize,
    pub protocol: MimcAbc<E>,
    pub sk: SecretKey<E>,
    pub vk: VerificationKey<E>,
}

impl<E: Pairing> Issuer<E> {
    /// Create a new issuer with a given ID and attribute count
    pub fn new(id: usize, num_attributes: usize, rng: &mut impl Rng) -> Self {
        let (protocol, sk, vk) = MimcAbc::<E>::setup(num_attributes, rng);
        Self {
            id,
            protocol,
            sk,
            vk,
        }
    }
}

/// Multi-issuer system manager
pub struct MultiIssuerSystem<E: Pairing> {
    pub issuers: HashMap<usize, Issuer<E>>,
}

impl<E: Pairing> MultiIssuerSystem<E> {
    /// Create a new multi-issuer system
    pub fn new() -> Self {
        Self {
            issuers: HashMap::new(),
        }
    }

    /// Add a new issuer to the system
    pub fn add_issuer(&mut self, issuer: Issuer<E>) {
        self.issuers.insert(issuer.id, issuer);
    }

    /// Generate multiple issuers for the system
    pub fn setup_issuers(
        &mut self,
        issuer_count: usize,
        attributes_per_issuer: &[usize],
        rng: &mut impl Rng,
    ) {
        for i in 0..issuer_count {
            let attr_count = if i < attributes_per_issuer.len() {
                attributes_per_issuer[i]
            } else {
                *attributes_per_issuer.last().unwrap_or(&10)
            };

            let issuer = Issuer::new(i, attr_count, rng);
            self.add_issuer(issuer);
        }
    }

    /// Get an issuer by ID
    pub fn get_issuer(&self, issuer_id: usize) -> Option<&Issuer<E>> {
        self.issuers.get(&issuer_id)
    }
}

/// Structure to represent a user with multiple credentials from various issuers
pub struct User<E: Pairing> {
    pub id: E::ScalarField,
    pub credentials: HashMap<(usize, usize), Credential<E>>, // (issuer_id, credential_id) -> Credential
}

impl<E: Pairing> User<E> {
    /// Create a new user with a random ID
    pub fn new(rng: &mut impl Rng) -> Self {
        let id = E::ScalarField::rand(rng);
        Self {
            id,
            credentials: HashMap::new(),
        }
    }

    /// Obtain a credential from a specific issuer
    pub fn obtain_credential(
        &mut self,
        issuer_id: usize,
        credential_id: usize,
        issuer_system: &MultiIssuerSystem<E>,
        attributes: Vec<E::ScalarField>,
        rng: &mut impl Rng,
    ) -> Result<(), Error> {
        let issuer = issuer_system
            .get_issuer(issuer_id)
            .ok_or_else(|| Error::Other(format!("Issuer {} not found", issuer_id)))?;

        // Create a credential with the user's ID as the first attribute
        let mut all_attributes = vec![self.id];
        all_attributes.extend(attributes);

        // Check if attribute count matches the issuer's expected count
        if all_attributes.len() != issuer.protocol.pp.n {
            return Err(Error::Other(format!(
                "Attribute count mismatch: expected {}, got {}",
                issuer.protocol.pp.n,
                all_attributes.len()
            )));
        }

        // Create the credential
        let r = E::ScalarField::rand(rng);
        let mut credential =
            Credential::new(&issuer.protocol.ck, &issuer.protocol.pp, &all_attributes, r);

        // Generate proof for issuance
        let proof = credential.prove_commitment(&issuer.protocol.pp, rng);

        // Get signature from issuer
        let signature = issuer.protocol.issue(&proof, &issuer.sk, rng)?;

        // Add signature to credential
        credential.add_signature(signature);

        // Store the credential
        self.credentials
            .insert((issuer_id, credential_id), credential);

        Ok(())
    }

    /// Show credentials from multiple issuers
    pub fn show_credentials(
        &self,
        credential_keys: &[(usize, usize)], // List of (issuer_id, credential_id) to show
        issuer_system: &MultiIssuerSystem<E>,
        rng: &mut impl Rng,
    ) -> Result<Vec<ShowCredential<E>>, Error> {
        let mut presentations = Vec::new();

        for (issuer_id, credential_id) in credential_keys {
            let credential = self
                .credentials
                .get(&(*issuer_id, *credential_id))
                .ok_or_else(|| {
                    Error::Other(format!(
                        "Credential ({}, {}) not found",
                        issuer_id, credential_id
                    ))
                })?;

            let issuer = issuer_system
                .get_issuer(*issuer_id)
                .ok_or_else(|| Error::Other(format!("Issuer {} not found", issuer_id)))?;

            let presentation = issuer.protocol.show(credential, rng);
            presentations.push(presentation);
        }

        Ok(presentations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;

    #[test]
    fn test_multi_issuer_system() {
        // Initialize random number generator
        let mut rng = ark_std::test_rng();

        // Create multi-issuer system
        let mut system = MultiIssuerSystem::<Bls12_381>::new();

        // Setup issuers with different attribute counts
        let attributes_per_issuer = [5, 10, 32];
        system.setup_issuers(3, &attributes_per_issuer, &mut rng);

        // Create a user
        let mut user = User::<Bls12_381>::new(&mut rng);

        // Obtain credentials from different issuers
        for issuer_id in 0..3 {
            let attr_count = attributes_per_issuer[issuer_id];
            let attributes: Vec<Fr> = (0..(attr_count - 1)).map(|_| Fr::rand(&mut rng)).collect();

            user.obtain_credential(issuer_id, 0, &system, attributes, &mut rng)
                .expect("Credential issuance should succeed");
        }

        // Show credentials from different issuers
        let credential_keys = vec![(0, 0), (1, 0), (2, 0)];
        let presentations = user
            .show_credentials(&credential_keys, &system, &mut rng)
            .expect("Credential presentation should succeed");

        // Verify each presentation
        for (i, presentation) in presentations.iter().enumerate() {
            let (issuer_id, _) = credential_keys[i];
            let issuer = system.get_issuer(issuer_id).unwrap();

            assert!(
                issuer.protocol.verify(presentation.clone(), &issuer.vk),
                "Credential verification should succeed"
            );
        }
    }
}
