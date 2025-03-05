use crate::commitment::Commitment;
use crate::keygen::{gen_keys_improved, SecretKeyImproved, VerificationKeyImproved};
use crate::proofsystem::{
    CommitmentProof, CommitmentProofError, CommitmentProofG2, CommitmentProofs,
};
use crate::publicparams::PublicParams;
use crate::signature::PSUTTSignatureImproved;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Neg;
use ark_std::rand::Rng;
use utils::pairing::verify_pairing_equation;

pub struct ShowCredentialImproved<E: Pairing> {
    pub randomized_signature: PSUTTSignatureImproved<E>,
    pub cmg1: E::G1Affine,
    pub proof: Vec<u8>,
}

/// User credential containing a secret key and commitment
pub struct UserCred<E: Pairing> {
    pub usk: E::ScalarField,
    pub commitment: Commitment<E>,
}

impl<E: Pairing> UserCred<E> {
    /// Create a new user credential with provided attributes
    pub fn new(
        pp: &PublicParams<E>,
        messages: &Vec<E::ScalarField>,
        usk: E::ScalarField,
    ) -> UserCred<E> {
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }

    /// Create a new user credential with random attributes
    pub fn new_random_messages(pp: &PublicParams<E>) -> UserCred<E> {
        let mut rng = ark_std::test_rng();
        let usk = E::ScalarField::rand(&mut rng);
        let messages: Vec<E::ScalarField> =
            (0..pp.n).map(|_| E::ScalarField::rand(&mut rng)).collect();
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }
}

/// Improved anonymous credential protocol with reduced pairing operations
pub struct AnonCredProtocolImproved<E: Pairing> {
    pub pp: PublicParams<E>,
    sk: SecretKeyImproved<E>,
    vk: VerificationKeyImproved<E>,
}

impl<E: Pairing> AnonCredProtocolImproved<E> {
    /// Create a new protocol instance with specified message count
    pub fn new(n: usize, rng: &mut impl Rng) -> Self {
        let context = E::ScalarField::rand(rng);
        let pp = PublicParams::<E>::new(&n, &context, rng);
        let (sk, vk) = gen_keys_improved(&pp, rng);
        Self { pp, sk, vk }
    }

    /// User generates proof of knowledge for obtaining a credential
    // User generates proof of knowledge in G1
    pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
        CommitmentProofs::pok_commitment_prove(&user_cred.commitment)
    }

    /// Issuer verifies proof of knowledge in G1 and verifies consistency of CM in G1 and G2. Issued Signature on G2 commitment.\
    pub fn issue(
        &self,
        cmg2: &E::G2Affine,
        serialized_proof: &[u8],
    ) -> Result<PSUTTSignatureImproved<E>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();

        // Verify proof of knowledge
        if !CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)? {
            return Err(CommitmentProofError::InvalidProof);
        }

        // Deserialize proof to access the commitment
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

        // Verify consistency of commitments - this checks e(proof.commitment, g2) = e(g1, cmg2)
        let is_consistent = verify_pairing_equation::<E>(
            &[
                (&proof.commitment, &self.pp.g2),
                (&self.pp.g1.into_group().neg().into_affine(), &cmg2),
            ],
            None,
        );

        // Guard against inconsistent commitments
        if !is_consistent {
            return Err(CommitmentProofError::InvalidCommitment);
        }

        // Sign the commitment
        Ok(PSUTTSignatureImproved::sign(
            &self.pp, &self.sk, &cmg2, &mut rng,
        ))
    }

    /// User shows credential by rerandomizing and creating presentation
    pub fn show<R: Rng>(
        &self,
        commitment: &Commitment<E>,
        signature: &PSUTTSignatureImproved<E>,
        rng: &mut R,
    ) -> Result<ShowCredentialImproved<E>, CommitmentProofError> {
        // Generate random values for rerandomization
        let r_delta = E::ScalarField::rand(rng);
        let u_delta = E::ScalarField::rand(rng);

        // Rerandomize the commitment and signature
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_signature = signature.rerandomize(&self.pp, &r_delta, &u_delta);

        // Create proof of knowledge for the rerandomized commitment
        let serialized_proof = CommitmentProofs::pok_commitment_prove(&randomized_commitment)?;

        Ok(ShowCredentialImproved {
            randomized_signature,
            cmg1: randomized_commitment.cmg1,
            proof: serialized_proof,
        })
    }

    /// Verifier checks credential presentation
    pub fn verify(
        &self,
        cred_show: &ShowCredentialImproved<E>,
    ) -> Result<bool, CommitmentProofError> {
        // Verify proof of knowledge
        if !CommitmentProofs::pok_commitment_verify::<E>(&cred_show.proof)? {
            return Ok(false);
        }

        // Verify signature
        Ok(cred_show
            .randomized_signature
            .verify_with_pairing_checker_improved(&self.pp, &self.vk, &cred_show.cmg1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    fn test_psutt_credential_lifecycle_improved() {
        // Setup phase
        let mut rng = test_rng();
        let message_count = 5;
        let protocol = AnonCredProtocolImproved::<Bls12_381>::new(message_count, &mut rng);

        // User phase - generate attributes and commitment
        let user_attributes: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let user_blinding = Fr::rand(&mut rng);
        let user_cred = UserCred::<Bls12_381>::new(&protocol.pp, &user_attributes, user_blinding);

        // Obtain phase - user creates proof of knowledge
        let proof = protocol
            .obtain(&user_cred)
            .expect("Failed to generate proof");

        // Issue phase - issuer verifies proof and issues credential
        let signature = protocol
            .issue(&user_cred.commitment.cmg2, &proof)
            .expect("Failed to issue credential");

        // Verify original signature
        assert!(
            signature.verify_with_pairing_checker_improved(
                &protocol.pp,
                &protocol.vk,
                &user_cred.commitment.cmg1,
            ),
            "Original signature verification failed"
        );

        // Show phase - user creates presentation
        let presentation = protocol
            .show(&user_cred.commitment, &signature, &mut rng)
            .expect("Failed to generate credential presentation");

        // Verify phase
        let is_valid = protocol
            .verify(&presentation)
            .expect("Verification process failed");

        assert!(is_valid, "Credential verification failed");
    }
}
