// mimc_abc/src/identity_binding.rs
use crate::commitment::Commitment;
use crate::error::Error;
use crate::public_params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

/// Proof that multiple commitments share the same value at index 0 (the user identifier)
pub struct IdentityBindingProof<E: Pairing> {
    /// The randomized commitments that are being proven over
    pub commitments: Vec<Commitment<E>>,
    /// Schnorr commitments for each credential (with shared blinding at position 0)
    pub schnorr_commitments: Vec<SchnorrCommitment<E::G1Affine>>,
    /// The challenge used in the proof
    pub challenge: E::ScalarField,
    /// Responses for each commitment
    pub responses: Vec<Vec<E::ScalarField>>,
}

impl<E: Pairing> IdentityBindingProof<E> {
    /// Create a proof that multiple commitments share the same value at position 0
    pub fn prove(
        commitments: &[Commitment<E>],
        messages: &[Vec<E::ScalarField>],
        randomness: &[E::ScalarField],
        public_params: &[&PublicParams<E>],
        rng: &mut impl Rng,
    ) -> Result<Self, Error> {
        // Check inputs
        if commitments.is_empty()
            || commitments.len() != messages.len()
            || commitments.len() != randomness.len()
            || commitments.len() != public_params.len()
        {
            return Err(Error::Other("Mismatched input lengths".to_string()));
        }

        // Ensure all messages have at least one element (the user ID)
        for msg in messages.iter() {
            if msg.is_empty() {
                return Err(Error::Other(
                    "Messages must have at least one element".to_string(),
                ));
            }
        }

        // Check that all first elements (user IDs) are identical
        let user_id = &messages[0][0];
        for msg in messages.iter().skip(1) {
            if &msg[0] != user_id {
                return Err(Error::Other(
                    "User identifiers must be identical".to_string(),
                ));
            }
        }

        // Generate a common blinding factor for position 0 (the user ID)
        let common_blinding = E::ScalarField::rand(rng);

        // Store schnorr commitments and prepare for responses
        let mut schnorr_commitments = Vec::with_capacity(commitments.len());

        // Generate Schnorr commitments for each credential
        for (i, commitment) in commitments.iter().enumerate() {
            let pp = public_params[i];
            let bases = pp.get_g1_bases();

            // Create blindings with common blinding at position 0
            let mut blindings: Vec<E::ScalarField> = (1..bases.len())
                .map(|_| E::ScalarField::rand(rng))
                .collect();

            // Insert the common blinding at the first position
            blindings.insert(0, common_blinding);

            // Create Schnorr commitment
            let schnorr_commitment =
                SchnorrProtocol::commit_with_prepared_blindings(&bases, &blindings);

            schnorr_commitments.push(schnorr_commitment);
        }

        // Generate a single challenge for all proofs
        let challenge = E::ScalarField::rand(rng);

        // Generate responses for each commitment
        let mut all_responses = Vec::with_capacity(commitments.len());
        for (i, commitment) in commitments.iter().enumerate() {
            // Create a vector with messages and randomness
            let mut exponents = messages[i].clone();
            exponents.push(randomness[i]);

            // Generate responses
            let responses = SchnorrProtocol::prove(&schnorr_commitments[i], &exponents, &challenge);
            all_responses.push(responses.0);
        }

        Ok(IdentityBindingProof {
            commitments: commitments.to_vec(),
            schnorr_commitments,
            challenge,
            responses: all_responses,
        })
    }

    /// Verify that multiple commitments share the same value at position 0
    pub fn verify(&self, public_params: &[&PublicParams<E>]) -> Result<bool, Error> {
        if self.commitments.is_empty()
            || self.commitments.len() != self.schnorr_commitments.len()
            || self.commitments.len() != self.responses.len()
            || self.commitments.len() != public_params.len()
        {
            return Err(Error::Other(
                "Mismatched proof component lengths".to_string(),
            ));
        }

        // Verify each individual Schnorr proof
        for i in 0..self.commitments.len() {
            let bases = public_params[i].get_g1_bases();

            // Verify the Schnorr proof
            let is_valid = SchnorrProtocol::verify_schnorr(
                &bases,
                &self.commitments[i].cm,
                &self.schnorr_commitments[i].commited_blindings,
                &self.responses[i],
                &self.challenge,
            );

            if !is_valid {
                return Ok(false);
            }
        }

        // Verify that all responses at position 0 are identical
        // This proves that the first attribute is the same in all commitments
        let first_response = &self.responses[0][0];
        for responses in self.responses.iter().skip(1) {
            if &responses[0] != first_response {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Module functions for simplified access
pub struct IdentityBinding;

impl IdentityBinding {
    /// Create a proof that multiple commitments share the same identity
    pub fn prove<E: Pairing>(
        commitments: &[Commitment<E>],
        messages: &[Vec<E::ScalarField>],
        randomness: &[E::ScalarField],
        public_params: &[&PublicParams<E>],
        rng: &mut impl Rng,
    ) -> Result<IdentityBindingProof<E>, Error> {
        IdentityBindingProof::prove(commitments, messages, randomness, public_params, rng)
    }

    /// Verify an identity binding proof
    pub fn verify<E: Pairing>(
        proof: &IdentityBindingProof<E>,
        public_params: &[&PublicParams<E>],
    ) -> Result<bool, Error> {
        proof.verify(public_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{Commitment, CommitmentKey};
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_identity_binding_proof() {
        let mut rng = test_rng();

        // Create multiple public parameters
        let n = 5; // Number of attributes in each commitment
        let pp1 = PublicParams::<Bls12_381>::new(&n, &mut rng);
        let pp2 = PublicParams::<Bls12_381>::new(&n, &mut rng);
        let pp3 = PublicParams::<Bls12_381>::new(&n, &mut rng);

        // Create commitment keys
        let ck1 = CommitmentKey {
            ck: pp1.ck.clone(),
            ck_tilde: pp1.ck_tilde.clone(),
        };
        let ck2 = CommitmentKey {
            ck: pp2.ck.clone(),
            ck_tilde: pp2.ck_tilde.clone(),
        };
        let ck3 = CommitmentKey {
            ck: pp3.ck.clone(),
            ck_tilde: pp3.ck_tilde.clone(),
        };

        // Generate a shared identity
        let user_id = Fr::rand(&mut rng);

        // Create messages with same identity at position 0
        let mut messages1 = vec![user_id];
        let mut messages2 = vec![user_id];
        let mut messages3 = vec![user_id];

        // Add random attributes
        for _ in 1..n {
            messages1.push(Fr::rand(&mut rng));
            messages2.push(Fr::rand(&mut rng));
            messages3.push(Fr::rand(&mut rng));
        }

        // Generate randomness
        let r1 = Fr::rand(&mut rng);
        let r2 = Fr::rand(&mut rng);
        let r3 = Fr::rand(&mut rng);

        // Create commitments
        let commitment1 = ck1.commit(&pp1, &messages1, &r1);
        let commitment2 = ck2.commit(&pp2, &messages2, &r2);
        let commitment3 = ck3.commit(&pp3, &messages3, &r3);

        // Create identity binding proof
        let proof = IdentityBinding::prove(
            &[
                commitment1.clone(),
                commitment2.clone(),
                commitment3.clone(),
            ],
            &[messages1.clone(), messages2, messages3],
            &[r1, r2, r3],
            &[&pp1, &pp2, &pp3],
            &mut rng,
        )
        .expect("Proof creation should succeed");

        // Verify the proof
        let is_valid = IdentityBinding::verify(&proof, &[&pp1, &pp2, &pp3])
            .expect("Verification should complete");

        assert!(
            is_valid,
            "Identity binding proof should verify successfully"
        );

        // Test negative case: different user ID
        let different_id = Fr::rand(&mut rng);
        let mut messages4 = vec![different_id]; // Different ID!
        for _ in 1..n {
            messages4.push(Fr::rand(&mut rng));
        }
        let r4 = Fr::rand(&mut rng);
        let commitment4 = ck1.commit(&pp1, &messages4, &r4);

        // This should fail during proof creation
        let invalid_proof_result = IdentityBinding::prove(
            &[commitment1, commitment4],
            &[messages1, messages4],
            &[r1, r4],
            &[&pp1, &pp1],
            &mut rng,
        );

        assert!(
            invalid_proof_result.is_err(),
            "Proof with different user IDs should fail"
        );
    }
}
