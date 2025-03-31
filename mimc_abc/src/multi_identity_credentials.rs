use crate::credential::Credential;
use crate::error::Error;
use crate::linked_credentials::LinkedCredentialPresentation;
use crate::multi_issuer::{MultiIssuerSystem, User};
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

/// Extension to User for creating linked presentations across issuers
impl<E: Pairing> User<E> {
    /// Show credentials from multiple issuers with proof of shared identity
    pub fn show_linked_credentials(
        &self,
        credential_keys: &[(usize, usize)], // List of (issuer_id, credential_id) to show
        issuer_system: &MultiIssuerSystem<E>,
        rng: &mut impl Rng,
    ) -> Result<LinkedCredentialPresentation<E>, Error> {
        // Collect credentials and public parameters
        let mut credentials = Vec::new();
        let mut public_params = Vec::new();

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

            credentials.push(credential);
            public_params.push(&issuer.protocol.pp);
        }

        // Convert Vec<Credential> to Vec<&Credential>
        let cred_refs: Vec<&Credential<E>> = credentials.iter().map(|c| &**c).collect();

        // Create a linked credential presentation
        LinkedCredentialPresentation::create(&cred_refs, &public_params, rng)
    }
}

/// Simple verification function for linked credentials
pub fn verify_linked_credentials<E: Pairing>(
    presentation: &LinkedCredentialPresentation<E>,
    issuer_system: &MultiIssuerSystem<E>,
    issuer_ids: &[usize],
) -> Result<bool, Error> {
    if presentation.credential_presentations.len() != issuer_ids.len() {
        return Err(Error::Other(
            "Mismatch between presentations and issuer IDs".to_string(),
        ));
    }

    // Collect verification keys and public parameters
    let mut verification_keys = Vec::new();
    let mut public_params = Vec::new();

    for issuer_id in issuer_ids {
        let issuer = issuer_system
            .get_issuer(*issuer_id)
            .ok_or_else(|| Error::Other(format!("Issuer {} not found", issuer_id)))?;

        verification_keys.push(&issuer.vk);
        public_params.push(&issuer.protocol.pp);
    }

    // Simply verify the presentation without any batching
    presentation.verify(&public_params, &verification_keys)
}
