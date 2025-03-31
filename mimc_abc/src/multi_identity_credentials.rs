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

use crate::multi_issuer::Issuer;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_std::test_rng;

#[test]
fn test_linked_identity_end_to_end() {
    // Initialize random number generator
    let mut rng = test_rng();

    // 1. Create a multi-issuer system
    let mut system = MultiIssuerSystem::<Bls12_381>::new();

    // Create issuers with different attribute counts
    println!("Creating issuers...");
    let issuer1 = Issuer::new(1, 5, &mut rng); // Issuer 1 with 5 attributes
    let issuer2 = Issuer::new(2, 8, &mut rng); // Issuer 2 with 8 attributes
    let issuer3 = Issuer::new(3, 4, &mut rng); // Issuer 3 with 4 attributes

    system.add_issuer(issuer1);
    system.add_issuer(issuer2);
    system.add_issuer(issuer3);
    println!("Created {} issuers", system.issuers.len());

    // 2. Create a user with a specific identity
    println!("Creating user...");
    let mut user = User::<Bls12_381>::new(&mut rng);
    let user_id = user.id; // The user's unique identifier
    println!("User created with ID: {:?}", user_id);

    // 3. User obtains credentials from each issuer
    println!("Obtaining credentials...");

    // From issuer 1 (5 attributes)
    let issuer1_attrs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
    user.obtain_credential(1, 101, &system, issuer1_attrs, &mut rng)
        .expect("Credential issuance from issuer 1 should succeed");

    // From issuer 2 (8 attributes)
    let issuer2_attrs: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect();
    user.obtain_credential(2, 202, &system, issuer2_attrs, &mut rng)
        .expect("Credential issuance from issuer 2 should succeed");

    // From issuer 3 (4 attributes)
    let issuer3_attrs: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut rng)).collect();
    user.obtain_credential(3, 303, &system, issuer3_attrs, &mut rng)
        .expect("Credential issuance from issuer 3 should succeed");

    println!("User obtained 3 credentials from different issuers");

    // 4. User creates a linked credential presentation
    println!("Creating linked credential presentation...");
    let credential_keys = vec![(1, 101), (2, 202), (3, 303)];
    let presentation = user
        .show_linked_credentials(&credential_keys, &system, &mut rng)
        .expect("Linked credential presentation should succeed");

    println!(
        "Created linked presentation with {} credentials",
        presentation.credential_presentations.len()
    );

    // 5. Verify the linked presentation
    println!("Verifying linked presentation...");
    let issuer_ids = vec![1, 2, 3];
    let is_valid = verify_linked_credentials(&presentation, &system, &issuer_ids)
        .expect("Verification should complete");

    assert!(is_valid, "Linked credential verification should succeed");
    println!("Linked credential presentation verified successfully!");

    // 6. Test negative case: Try to create presentation with a credential with different ID
    println!("Testing negative case...");

    // Create a new user with a different ID
    let mut other_user = User::<Bls12_381>::new(&mut rng);

    // User obtains credential from issuer 1
    let other_attrs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
    other_user
        .obtain_credential(1, 101, &system, other_attrs, &mut rng)
        .expect("Credential issuance for other user should succeed");

    // Try to create a presentation with credentials from both users (different IDs)
    let mismatched_creds = vec![
        user.credentials.get(&(2, 202)).unwrap(),
        user.credentials.get(&(3, 303)).unwrap(),
        other_user.credentials.get(&(1, 101)).unwrap(),
    ];

    let mismatched_params = vec![
        &system.get_issuer(2).unwrap().protocol.pp,
        &system.get_issuer(3).unwrap().protocol.pp,
        &system.get_issuer(1).unwrap().protocol.pp,
    ];

    // This should fail because the user IDs don't match
    let refs: Vec<&Credential<Bls12_381>> = mismatched_creds.iter().map(|c| &**c).collect();
    let invalid_presentation =
        LinkedCredentialPresentation::create(&refs, &mismatched_params, &mut rng);

    assert!(
        invalid_presentation.is_err(),
        "Creating linked presentation with different user IDs should fail"
    );
    println!("Successfully prevented presentation with different user IDs!");
}
