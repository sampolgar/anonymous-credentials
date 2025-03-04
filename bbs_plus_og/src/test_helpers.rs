use crate::keygen::{gen_keys, PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use crate::signature::BBSPlusOgSignature;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

/// Test setup structure that generates all the necessary components for testing
pub struct TestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub sk: SecretKey<E>,
    pub pk: PublicKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub signature: BBSPlusOgSignature<E>,
}

impl<E: Pairing> TestSetup<E> {
    /// Create a new test setup with random parameters
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `message_count` - Number of messages to include in the setup
    ///
    /// # Returns
    /// * Test setup with all necessary components
    pub fn new(rng: &mut impl Rng, message_count: usize) -> Self {
        // Generate public parameters with specified message count
        let pp = PublicParams::<E>::new(&message_count, rng);

        // Generate keypair
        let (sk, pk) = gen_keys(&pp, rng);

        // Generate random messages
        let messages: Vec<E::ScalarField> = (0..message_count)
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        // Sign the messages
        let signature = BBSPlusOgSignature::sign(&pp, &sk, &messages, rng);

        TestSetup {
            pp,
            sk,
            pk,
            messages,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::test_rng;

    #[test]
    fn test_setup_creation() {
        let mut rng = test_rng();
        let message_count = 4;

        // Create test setup
        let setup = TestSetup::<Bls12_381>::new(&mut rng, message_count);

        // Verify the signature
        let is_valid = setup
            .signature
            .verify(&setup.pp, &setup.pk, &setup.messages);

        assert!(is_valid, "Signature in test setup should be valid");
        assert_eq!(
            setup.messages.len(),
            message_count,
            "Should have the requested message count"
        );
    }
}
