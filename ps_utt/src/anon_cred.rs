use crate::commitment::Commitment;
use crate::keygen::{
    gen_keys, gen_keys_improved, SecretKey, SecretKeyImproved, VerificationKey,
    VerificationKeyImproved,
};
use crate::proofsystem::{
    CommitmentProof, CommitmentProofError, CommitmentProofG2, CommitmentProofs,
};
use crate::publicparams::PublicParams;
use crate::signature::{PSUTTSignature, PSUTTSignatureImproved};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};

pub struct UserCred<E: Pairing> {
    pub usk: E::ScalarField,
    pub commitment: Commitment<E>,
}

pub struct ShowCredential<E: Pairing> {
    pub randomized_signature: PSUTTSignature<E>,
    pub cmg1: E::G1Affine,
    pub cmg2: E::G2Affine,
    pub proof: Vec<u8>,
}

pub struct ShowCredentialImproved<E: Pairing> {
    pub randomized_signature: PSUTTSignatureImproved<E>,
    pub cmg1: E::G1Affine,
    pub proof: Vec<u8>,
}

impl<E: Pairing> UserCred<E> {
    pub fn new(
        pp: &PublicParams<E>,
        messages: &Vec<E::ScalarField>,
        usk: E::ScalarField,
    ) -> UserCred<E> {
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }

    pub fn new_random_messages(pp: &PublicParams<E>) -> UserCred<E> {
        let mut rng = ark_std::test_rng();
        let usk = E::ScalarField::rand(&mut rng);
        let messages: Vec<E::ScalarField> =
            (0..pp.n).map(|_| E::ScalarField::rand(&mut rng)).collect();
        let commitment = Commitment::new(&pp, &messages, &usk);
        Self { usk, commitment }
    }
}

pub struct AnonCredProtocol<E: Pairing> {
    pub pp: PublicParams<E>,
    sk: SecretKey<E>,
    vk: VerificationKey<E>,
}

impl<E: Pairing> AnonCredProtocol<E> {
    pub fn new(n: usize, rng: &mut impl Rng) -> Self {
        let context = E::ScalarField::rand(rng);
        let pp = PublicParams::<E>::new(&n, &context, rng);
        let (sk, vk) = gen_keys(&pp, rng);
        Self { pp, sk, vk }
    }

    pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
        let proof = CommitmentProofs::pok_commitment_prove(&user_cred.commitment)?;
        let mut serialized_proof = Vec::new();
        println!("serializing proof ------------------");
        proof.serialize_compressed(&mut serialized_proof)?;
        // Debug: Test test proofs
        let result = CommitmentProofs::pok_commitment_verify::<E>(&serialized_proof)?;
        if !result {
            return Err(CommitmentProofError::InvalidProof);
        }
        println!("proof was valid ------------------");
        // Debug: Test deserialization immediately
        let deserialized_proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof[..])?;
        println!("Serialized proof length: {}", serialized_proof.len());
        assert_eq!(
            deserialized_proof.commitment, user_cred.commitment.cmg1,
            "cmg1, not eq cmg1"
        );
        Ok(serialized_proof)
    }

    pub fn issue(
        &self,
        serialized_proof: &[u8],
    ) -> Result<PSUTTSignature<E>, CommitmentProofError> {
        let mut rng = ark_std::test_rng();
        let deserialized_proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(&serialized_proof[..])?;

        let result = CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)?;
        if !result {
            return Err(CommitmentProofError::InvalidProof);
        }
        let proof: CommitmentProof<E> =
            CanonicalDeserialize::deserialize_compressed(serialized_proof)?;
        Ok(PSUTTSignature::sign(
            &self.pp,
            &self.sk,
            &proof.commitment,
            &mut rng,
        ))
    }

    // pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
    //     // Generate proof of knowledge of the commitment opening
    //     let proof = CommitmentProofs::pok_commitment_prove(&user_cred.commitment)?;
    //     let mut serialized_proof = Vec::new();
    //     proof.serialize_compressed(&mut serialized_proof)?;
    //     Ok(serialized_proof)
    // }

    // pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
    //     let proof = CommitmentProofs::pok_commitment_prove(&user_cred.commitment)?;
    //     let mut serialized_proof = Vec::new();
    //     proof.serialize_compressed(&mut serialized_proof)?;
    //     // Debug: Test deserialization immediately
    //     let deserialized_proof: CommitmentProof<E> =
    //         CanonicalDeserialize::deserialize_compressed(&serialized_proof[..])?;
    //     println!("Serialized proof length: {}", serialized_proof.len());
    //     Ok(serialized_proof)
    // }

    // pub fn issue(
    //     &self,
    //     serialized_proof: &[u8],
    // ) -> Result<PSUTTSignature<E>, CommitmentProofError> {
    //     let mut rng = ark_std::test_rng();
    //     let result = CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)?;

    //     if !result {
    //         return Err(CommitmentProofError::InvalidProof);
    //     }

    //     let proof: CommitmentProof<E> =
    //         CanonicalDeserialize::deserialize_compressed(serialized_proof)?;
    //     // if result is valid
    //     Ok(PSUTTSignature::sign(
    //         &self.pp,
    //         &self.sk,
    //         &proof.commitment,
    //         &mut rng,
    //     ))
    // }

    // pub fn issue(
    //     &self,
    //     serialized_proof: &[u8],
    // ) -> Result<PSUTTSignature<E>, CommitmentProofError> {
    //     let mut rng = ark_std::test_rng();
    //     println!("Issue: Serialized proof length: {}", serialized_proof.len());
    //     let result = CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)?;
    //     if !result {
    //         return Err(CommitmentProofError::InvalidProof);
    //     }
    //     let proof: CommitmentProof<E> =
    //         CanonicalDeserialize::deserialize_compressed(serialized_proof)?;
    //     Ok(PSUTTSignature::sign(
    //         &self.pp,
    //         &self.sk,
    //         &proof.commitment,
    //         &mut rng,
    //     ))
    // }

    pub fn show<R: Rng>(
        &self,
        commitment: &Commitment<E>,
        signature: &PSUTTSignature<E>,
        rng: &mut R,
    ) -> Result<ShowCredential<E>, CommitmentProofError> {
        // Generate random values for rerandomization
        let r_delta = E::ScalarField::rand(rng);
        let u_delta = E::ScalarField::rand(rng);

        // Rerandomize the commitment
        let randomized_commitment = commitment.create_randomized(&r_delta);

        // Rerandomize the signature
        let randomized_signature = signature.rerandomize(&self.pp, &r_delta, &u_delta);

        // Create a proof of knowledge for the rerandomized commitment
        let proof = CommitmentProofs::pok_commitment_prove(&randomized_commitment)?;

        // Serialize the proof
        let mut serialized_proof = Vec::new();
        proof.serialize_compressed(&mut serialized_proof)?;

        Ok(ShowCredential {
            randomized_signature,
            cmg1: randomized_commitment.cmg1,
            cmg2: randomized_commitment.cmg2,
            proof: serialized_proof,
        })
    }

    pub fn verify(&self, cred_show: &ShowCredential<E>) -> Result<bool, CommitmentProofError> {
        // Verify proof of knowledge
        let proof_valid = CommitmentProofs::pok_commitment_verify::<E>(&cred_show.proof)?;
        if !proof_valid {
            return Ok(false);
        }

        // Verify signature
        Ok(cred_show.randomized_signature.verify_with_pairing_checker(
            &self.pp,
            &self.vk,
            &cred_show.cmg1,
            &cred_show.cmg2,
        ))
    }
}

// pub struct AnonCredProtocolImproved<E: Pairing> {
//     pub pp: PublicParams<E>,
//     sk: SecretKeyImproved<E>,
//     vk: VerificationKeyImproved<E>,
// }

// impl<E: Pairing> AnonCredProtocolImproved<E> {
//     pub fn new(n: usize, rng: &mut impl Rng) -> Self {
//         let context = E::ScalarField::rand(rng);
//         let pp = PublicParams::<E>::new(&n, &context, rng);
//         let (sk, vk) = gen_keys_improved(&pp, rng);
//         Self { pp, sk, vk }
//     }

//     pub fn obtain(&self, user_cred: &UserCred<E>) -> Result<Vec<u8>, CommitmentProofError> {
//         // Generate proof of knowledge of the commitment opening
//         let proof = CommitmentProofs::pok_commitment_prove_g2(&user_cred.commitment)?;
//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;
//         Ok(serialized_proof)
//     }

//     pub fn issue(
//         &self,
//         serialized_proof: &[u8],
//     ) -> Result<PSUTTSignatureImproved<E>, CommitmentProofError> {
//         let mut rng = ark_std::test_rng();

//         let result = CommitmentProofs::pok_commitment_verify::<E>(serialized_proof)?;
//         if !result {
//             return Err(CommitmentProofError::InvalidProof);
//         }

//         let proof: CommitmentProofG2<E> =
//             CanonicalDeserialize::deserialize_compressed(serialized_proof)?;

//         // if result is valid
//         Ok(PSUTTSignatureImproved::sign(
//             &self.pp,
//             &self.sk,
//             &proof.commitment,
//             &mut rng,
//         ))
//     }

//     pub fn show<R: Rng>(
//         &self,
//         commitment: &Commitment<E>,
//         signature: &PSUTTSignatureImproved<E>,
//         rng: &mut R,
//     ) -> Result<ShowCredentialImproved<E>, CommitmentProofError> {
//         // Generate random values for rerandomization
//         let r_delta = E::ScalarField::rand(rng);
//         let u_delta = E::ScalarField::rand(rng);

//         // Rerandomize the commitment
//         let randomized_commitment = commitment.create_randomized(&r_delta);

//         // Rerandomize the signature
//         let randomized_signature = signature.rerandomize(&self.pp, &r_delta, &u_delta);

//         // Create a proof of knowledge for the rerandomized commitment
//         let proof = CommitmentProofs::pok_commitment_prove_g2(&randomized_commitment)?;

//         // Serialize the proof
//         let mut serialized_proof = Vec::new();
//         proof.serialize_compressed(&mut serialized_proof)?;

//         Ok(ShowCredentialImproved {
//             randomized_signature,
//             cmg1: randomized_commitment.cmg1,
//             proof: serialized_proof,
//         })
//     }

//     pub fn verify(
//         &self,
//         cred_show: &ShowCredentialImproved<E>,
//     ) -> Result<bool, CommitmentProofError> {
//         // Verify proof of knowledge
//         let proof_valid = CommitmentProofs::pok_commitment_verify::<E>(&cred_show.proof)?;
//         if !proof_valid {
//             return Ok(false);
//         }

//         // Verify signature
//         Ok(cred_show
//             .randomized_signature
//             .verify_with_pairing_checker_improved(&self.pp, &self.vk, &cred_show.cmg1))
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    #[test]
    fn test_psutt_credential_lifecycle() {
        // Setup phase - establish protocol parameters and key material
        let mut rng = test_rng();
        let message_count = 5; // Credentials with 5 attributes
        let protocol = AnonCredProtocol::<Bls12_381>::new(message_count, &mut rng);

        // User phase - generate attributes and commitment
        let user_attributes: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let user_blinding = Fr::rand(&mut rng);
        let user_cred = UserCred::<Bls12_381>::new(&protocol.pp, &user_attributes, user_blinding);

        // Obtain phase - user creates proof of knowledge of commitment
        let proof = protocol
            .obtain(&user_cred)
            .expect("Failed to generate proof");

        // Issue phase - issuer verifies proof and issues credential
        let signature = protocol.issue(&proof).expect("Failed to issue credential");

        // Verify original signature directly to confirm issuance worked
        assert!(
            signature.verify_with_pairing_checker(
                &protocol.pp,
                &protocol.vk,
                &user_cred.commitment.cmg1,
                &user_cred.commitment.cmg2
            ),
            "Original signature verification failed"
        );

        // Show phase - user rerandomizes credential and generates presentation
        let presentation = protocol
            .show(&user_cred.commitment, &signature, &mut rng)
            .expect("Failed to generate credential presentation");

        // Verify phase - verifier checks the presentation
        let is_valid = protocol
            .verify(&presentation)
            .expect("Verification process failed");

        // Assert the presentation verifies correctly
        assert!(is_valid, "Credential verification failed");
    }
}
