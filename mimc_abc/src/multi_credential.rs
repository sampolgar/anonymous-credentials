// mimc_abc/src/multi_credential.rs
use crate::commitment::Commitment;
use crate::credential::{Credential, ShowCredential};
use crate::error::Error;
use crate::proof::CommitmentProof;
use crate::public_params::PublicParams;
use crate::signature::{Signature, VerificationKey};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::ops::{Add, Mul, Neg};
use ark_std::rand::Rng;
use ark_std::One;
use utils::pairing::PairingCheck;

/// Aggregate presentation of multiple credentials from the same issuer
pub struct AggregatePresentation<E: Pairing> {
    pub randomized_signatures: Vec<Signature<E>>,
    pub randomized_commitments: Vec<Commitment<E>>,
    pub proofs: Vec<CommitmentProof<E>>,
}

impl<E: Pairing> AggregatePresentation<E> {
    /// Create a new aggregate presentation from individual ShowCredential presentations
    pub fn new(presentations: Vec<ShowCredential<E>>) -> Self {
        let randomized_signatures = presentations
            .iter()
            .map(|p| p.randomized_signature.clone())
            .collect();
        let randomized_commitments = presentations
            .iter()
            .map(|p| p.randomized_commitment.clone())
            .collect();
        let proofs = presentations.iter().map(|p| p.proof.clone()).collect();

        Self {
            randomized_signatures,
            randomized_commitments,
            proofs,
        }
    }

    /// Verify all credentials in the presentation
    /// Standard approach - verify each credential individually
    pub fn verify_all(&self, pp: &PublicParams<E>, vk: &VerificationKey<E>) -> bool {
        // First verify all individual proofs
        for proof in &self.proofs {
            if !proof.verify() {
                return false;
            }
        }

        // Then verify all signatures
        for (i, signature) in self.randomized_signatures.iter().enumerate() {
            if !vk.verify(signature, &self.randomized_commitments[i], pp) {
                return false;
            }
        }

        true
    }

    /// Batch verify all credentials using pairing optimization
    /// This is more efficient for multiple credentials from the same issuer
    pub fn batch_verify(&self, pp: &PublicParams<E>, vk: &VerificationKey<E>) -> bool {
        // First verify all individual proofs
        for proof in &self.proofs {
            if !proof.verify() {
                return false;
            }
        }

        // Set up a pairing checker for batch verification
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);
        let mut final_check = PairingCheck::<E>::new();

        // For each signature, create a random weight for the batch verification
        for (i, signature) in self.randomized_signatures.iter().enumerate() {
            // Generate a random weight for this signature
            let mut rng = ark_std::rand::thread_rng();
            let weight = E::ScalarField::rand(&mut rng);

            // Calculate vk + commitment in G2
            let vk_plus_cm_tilde = vk
                .vk_tilde
                .add(self.randomized_commitments[i].cm_tilde)
                .into_affine();

            // Add the pairing check for this signature with the random weight
            let sig_check = PairingCheck::<E>::rand(
                &mr,
                &[
                    (&signature.sigma2.mul(weight).into_affine(), &pp.g_tilde),
                    (
                        &signature.sigma1.mul(weight).neg().into_affine(),
                        &vk_plus_cm_tilde,
                    ),
                ],
                &E::TargetField::one(),
            );

            // Add commitment consistency check
            let cm_check = PairingCheck::<E>::rand(
                &mr,
                &[
                    (
                        &self.randomized_commitments[i].cm.mul(weight).into_affine(),
                        &pp.g_tilde,
                    ),
                    (
                        &pp.g.mul(weight).neg().into_affine(),
                        &self.randomized_commitments[i].cm_tilde,
                    ),
                ],
                &E::TargetField::one(),
            );

            final_check.merge(&sig_check);
            final_check.merge(&cm_check);
        }

        // Verify all pairing equations at once
        final_check.verify()
    }
}

/// Helper functions for credential aggregation
pub struct CredentialAggregation;

impl CredentialAggregation {
    /// Create an aggregate presentation from multiple credentials
    pub fn aggregate_credentials<E: Pairing>(
        credentials: &[Credential<E>],
        pp: &PublicParams<E>,
        rng: &mut impl Rng,
    ) -> Result<AggregatePresentation<E>, Error> {
        // Create individual presentations
        let mut presentations = Vec::new();

        for credential in credentials {
            // Generate random values for each credential
            let delta_r = E::ScalarField::rand(rng);
            let delta_u = E::ScalarField::rand(rng);

            // Create a presentation
            let presentation = credential.show(pp, &delta_r, &delta_u, rng);
            presentations.push(presentation);
        }

        // Aggregate the presentations
        Ok(AggregatePresentation::new(presentations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MimcAbc;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_multiple_credentials_batch_verification() {
        // Setup
        let mut rng = test_rng();
        let n = 10; // Attributes per credential
        let credential_count = 5; // Number of credentials
        let (protocol, issuer_sk, issuer_vk) = MimcAbc::<Bls12_381>::setup(n, &mut rng);

        // Create multiple credentials for the same user
        let user_id = Fr::rand(&mut rng);
        let mut credentials = Vec::new();

        for _ in 0..credential_count {
            // Create random attributes (with user_id as first attribute)
            let mut attributes = vec![user_id];
            for _ in 1..n {
                attributes.push(Fr::rand(&mut rng));
            }

            // Create credential
            let r = Fr::rand(&mut rng);
            let mut credential = Credential::new(&protocol.ck, &protocol.pp, &attributes, r);

            // Issue credential
            let proof = credential.prove_commitment(&protocol.pp, &mut rng);
            let signature = protocol.issue(&proof, &issuer_sk, &mut rng).unwrap();
            credential.add_signature(signature);

            // Verify individual credential
            assert!(
                credential.verify(&protocol.pp, &issuer_vk),
                "Individual credential verification failed"
            );

            credentials.push(credential);
        }

        // Aggregate the credentials
        let aggregate =
            CredentialAggregation::aggregate_credentials(&credentials, &protocol.pp, &mut rng)
                .unwrap();

        // Verify using standard approach
        let standard_start = std::time::Instant::now();
        let standard_result = aggregate.verify_all(&protocol.pp, &issuer_vk);
        let standard_time = standard_start.elapsed();

        // Verify using batch approach
        let batch_start = std::time::Instant::now();
        let batch_result = aggregate.batch_verify(&protocol.pp, &issuer_vk);
        let batch_time = batch_start.elapsed();

        // Both should succeed
        assert!(standard_result, "Standard verification failed");
        assert!(batch_result, "Batch verification failed");

        println!(
            "Verification times for {} credentials - Standard: {:?}, Batch: {:?}",
            credential_count, standard_time, batch_time
        );
    }
}
