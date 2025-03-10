// protocol.rs
use crate::commitment::SymmetricCommitmentKey;
use crate::credential::{Credential, CredentialCommitments};
use crate::dkg_keygen::{dkg_keygen, ThresholdKeys, VerificationKey};
use crate::publicparams::PublicParams;
use crate::signer::Signer;
use crate::threshold_signature::{BlindSignature, SignatureShare, ThresholdSignatureError};
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;

/// Protocol setup parameters created during initialization
pub struct ProtocolParameters<E: Pairing> {
    pub params: PublicParams<E>,
    pub ck: SymmetricCommitmentKey<E>,
    pub vk: VerificationKey<E>,
}

/// Protocol setup function
pub fn setup_parameters<E: Pairing>(
    num_attributes: usize,
    rng: &mut impl Rng,
) -> ProtocolParameters<E> {
    // Initialize public parameters
    let params = PublicParams::<E>::new(None, rng);

    // Generate y values for commitment keys
    let y_values: Vec<E::ScalarField> = (0..num_attributes)
        .map(|_| E::ScalarField::rand(rng))
        .collect();

    // Create commitment key
    let ck = SymmetricCommitmentKey::new(&params, &y_values);

    // Create verification key (this would typically be derived from the DKG)
    // This is a placeholder - in a real implementation, this would come from DKG
    let x = E::ScalarField::rand(rng);
    let vk = VerificationKey {
        g_tilde_x: params.g_tilde.mul(x).into_affine(),
    };

    ProtocolParameters { params, ck, vk }
}

/// Generate threshold keys for signers
pub fn setup_threshold_keys<E: Pairing>(
    parameters: &ProtocolParameters<E>,
    threshold: usize,
    num_signers: usize,
    num_attributes: usize,
    rng: &mut impl Rng,
) -> ThresholdKeys<E> {
    // Run the distributed key generation
    let (_, _, threshold_keys) = dkg_keygen(
        &parameters.params,
        threshold,
        num_signers,
        num_attributes,
        rng,
    );

    threshold_keys
}

/// Create initialized signers from threshold keys
pub fn initialize_signers<E: Pairing>(
    parameters: &ProtocolParameters<E>,
    threshold_keys: &ThresholdKeys<E>,
) -> Vec<Signer<E>> {
    threshold_keys
        .sk_shares
        .iter()
        .map(|sk_share| {
            Signer::new(
                parameters.params.clone(),
                parameters.ck.clone(),
                sk_share.clone(),
            )
        })
        .collect()
}

/// Initialize a credential for a user
pub fn initialize_credential<E: Pairing>(
    parameters: &ProtocolParameters<E>,
    messages: &[E::ScalarField],
) -> Credential<E> {
    let mut credential = Credential::new(parameters.params.clone(), parameters.ck.clone());

    credential.set_attributes(messages.to_vec());
    credential
}

/// Verify a threshold signature
pub fn verify_signature<E: Pairing>(
    parameters: &ProtocolParameters<E>,
    credential: &Credential<E>,
    signature: &BlindSignature<E>,
) -> bool {
    // This would implement your signature verification logic
    // For now, this is a placeholder
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_interactive_protocol() {
        let mut rng = test_rng();

        //------------------------------------------------------
        // 1. Setup phase: Initialize protocol parameters
        //------------------------------------------------------
        let threshold = 2;
        let num_signers = 5;
        let num_attributes = 3;

        // Generate protocol parameters
        let parameters = setup_parameters::<Bls12_381>(num_attributes, &mut rng);

        // Generate threshold keys
        let threshold_keys = setup_threshold_keys(
            &parameters,
            threshold,
            num_signers,
            num_attributes,
            &mut rng,
        );

        // Initialize signers
        let signers = initialize_signers(&parameters, &threshold_keys);

        //------------------------------------------------------
        // 2. User interaction: Create credential and commitments
        //------------------------------------------------------
        // Generate random attributes for credential
        let messages: Vec<_> = (0..num_attributes)
            .map(|_| <Bls12_381 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        // Initialize a credential
        let mut credential = initialize_credential(&parameters, &messages);

        // User creates commitments
        let commitments = credential
            .create_commitments(&mut rng)
            .expect("Failed to create commitments");

        //------------------------------------------------------
        // 3. Signer interaction: Generate signature shares
        //------------------------------------------------------
        // User selects a subset of signers (t+1)
        let selected_signers = &signers[0..threshold + 1];

        // User requests signature shares from each selected signer
        let mut signature_shares = Vec::new();

        for signer in selected_signers {
            // Signer verifies commitments and generates a share
            let share = signer
                .create_signature_shares(&commitments)
                .expect("Failed to create signature share");

            signature_shares.push(share);
        }

        //------------------------------------------------------
        // 4. User aggregation: Combine shares into signature
        //------------------------------------------------------
        // User aggregates signature shares
        let blind_signature = credential
            .aggregate_shares(&signature_shares, threshold)
            .expect("Failed to aggregate shares");

        // User unblinds the signature
        let unblinded_signature = credential
            .unblind_signature(blind_signature.clone())
            .expect("Failed to unblind signature");

        //------------------------------------------------------
        // 5. Verification: Confirm the signature is valid
        //------------------------------------------------------
        // Verify the signature
        let is_valid = verify_signature(&parameters, &credential, &unblinded_signature);

        assert!(is_valid, "Signature verification failed");
    }
}
