use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_r1cs_std::fields::nonnative::params;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use utils::helpers::Helpers;

#[derive(Clone, Debug)]
pub struct CommitmentKey<E: Pairing> {
    pub h1: E::G1Affine,
    pub h2: E::G2Affine,
    pub g1_y: Vec<E::G1Affine>, //[Y_1, Y_2, ..., Y_n]
    pub g2_y: Vec<E::G2Affine>, //[Y_1, Y_2, ..., Y_n]
}

pub struct CommitmentScheme<E: Pairing> {
    pub ck: CommitmentKey<E>,
}

impl<E: Pairing> CommitmentScheme<E> {
    pub fn setup<R: Rng>(m_count: usize, rng: &mut R) -> Self {
        let h1 = E::G1Affine::rand(rng);
        let h2 = E::G2Affine::rand(rng);
        let yi: Vec<E::ScalarField> = (0..m_count).map(|_| E::ScalarField::rand(rng)).collect();

        let g1_y = E::G1::normalize_batch(&yi.iter().map(|yi| h1.mul(*yi)).collect::<Vec<_>>());
        let g2_y = E::G2::normalize_batch(&yi.iter().map(|yi| h2.mul(*yi)).collect::<Vec<_>>());

        Self {
            ck: CommitmentKey { h1, h2, g1_y, g2_y },
        }
    }

    pub fn commit(&self, messages: &[E::ScalarField], r: E::ScalarField) -> Commitment<E> {
        Commitment::new(messages.to_vec(), r, &self.ck)
    }

    // Verify G1 G2 Pairing Consistency
    pub fn verify_commitment(&self, commitment: &Commitment<E>) -> bool {
        // Verify commitment consistency using pairing
        let pairing1 = E::pairing(commitment.g1_cm, self.ck.h2);
        let pairing2 = E::pairing(self.ck.h1, commitment.g2_cm);
        pairing1 == pairing2
    }
}

// Individual commitment instance
pub struct Commitment<E: Pairing> {
    messages: Vec<E::ScalarField>,
    r: E::ScalarField,
    pub g1_cm: E::G1Affine,
    pub g2_cm: E::G2Affine,
}

impl<E: Pairing> Commitment<E> {
    fn new(messages: Vec<E::ScalarField>, r: E::ScalarField, ck: &CommitmentKey<E>) -> Self {
        let g1_cm = Helpers::commit_g1::<E>(&r, &messages, &ck.g1_y, &ck.h1);
        let g2_cm = Helpers::commit_g2::<E>(&r, &messages, &ck.g2_y, &ck.h2);

        Self {
            messages,
            r,
            g1_cm,
            g2_cm,
        }
    }

    pub fn rerandomize(&self, ck: &CommitmentKey<E>, delta_r: E::ScalarField) -> Self {
        let g1_randomized = ck.h1.mul(delta_r).add(self.g1_cm).into_affine();
        let g2_randomized = ck.h2.mul(delta_r).add(self.g2_cm).into_affine();
        let r_prime = self.r + delta_r;

        Self {
            messages: self.messages.clone(),
            r: r_prime,
            g1_cm: g1_randomized,
            g2_cm: g2_randomized,
        }
    }
}

// PS Signature scheme that works with commitments
pub struct PSSignatureScheme<E: Pairing> {
    pub commitment_scheme: CommitmentScheme<E>,
    pub sk: E::G1Affine,
    pub vk: E::G2Affine,
}

pub struct Signature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> PSSignatureScheme<E> {
    pub fn setup<R: Rng>(m_count: usize, rng: &mut R) -> Self {
        let commitment_scheme = CommitmentScheme::<E>::setup(m_count, rng);
        let x = E::ScalarField::rand(rng);
        let sk = commitment_scheme.ck.h1.mul(x).into_affine();
        let vk = commitment_scheme.ck.h2.mul(x).into_affine();

        Self {
            commitment_scheme,
            sk,
            vk,
        }
    }

    pub fn sign(&self, commitment: &Commitment<E>) -> Signature<E> {
        let u = E::ScalarField::rand(&mut ark_std::rand::thread_rng());
        let sigma1 = self.commitment_scheme.ck.h1.mul(u).into_affine();
        let sigma2 = (self.sk.add(commitment.g1_cm)).mul(u).into_affine();

        Signature { sigma1, sigma2 }
    }

    pub fn verify(&self, signature: &Signature<E>, commitment: &Commitment<E>) -> bool {
        let pairing1 = E::pairing(signature.sigma2, self.commitment_scheme.ck.h2);
        let pairing2 = E::pairing(
            signature.sigma1,
            self.vk.add(commitment.g2_cm).into_affine(),
        );
        pairing1 == pairing2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    type E = Bls12_381;

    #[test]
    fn test_commitment_scheme_operations() {
        let mut rng = thread_rng();
        let m_count = 3;

        // Setup commitment scheme
        let scheme = CommitmentScheme::<E>::setup(m_count, &mut rng);

        // Create random messages
        let messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);

        // Create commitment
        let commitment = scheme.commit(&messages, r);

        // Test 1: Verify commitment consistency
        assert!(
            scheme.verify_commitment(&commitment),
            "Commitment verification failed"
        );

        // Test 2: Rerandomization
        let delta_r = Fr::rand(&mut rng);
        let rerandomized_commitment = commitment.rerandomize(&scheme.ck, delta_r);

        // Verify rerandomized commitment is still valid
        assert!(
            scheme.verify_commitment(&rerandomized_commitment),
            "Rerandomized commitment verification failed"
        );

        // Test 3: Different randomness produces different commitments
        let r2 = Fr::rand(&mut rng);
        let commitment2 = scheme.commit(&messages, r2);
        assert_ne!(
            commitment.g1_cm, commitment2.g1_cm,
            "Different randomness should produce different commitments"
        );

        // Test 4: Same messages and randomness produce same commitment
        let commitment3 = scheme.commit(&messages, r);
        assert_eq!(
            commitment.g1_cm, commitment3.g1_cm,
            "Same messages and randomness should produce same commitment"
        );
    }

    #[test]
    fn test_ps_signature_operations() {
        let mut rng = thread_rng();
        let m_count = 3;

        // Setup PS signature scheme
        let ps_scheme = PSSignatureScheme::<E>::setup(m_count, &mut rng);

        // Create a commitment to sign
        let messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = ps_scheme.commitment_scheme.commit(&messages, r);

        // Test 1: Sign and verify
        let signature = ps_scheme.sign(&commitment);
        assert!(
            ps_scheme.verify(&signature, &commitment),
            "Signature verification failed"
        );

        // Test 2: Verify signature fails with different commitment
        let different_messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();
        let different_commitment = ps_scheme
            .commitment_scheme
            .commit(&different_messages, Fr::rand(&mut rng));
        assert!(
            !ps_scheme.verify(&signature, &different_commitment),
            "Signature verification should fail with different commitment"
        );

        // Test 3: Verify signature with rerandomized commitment
        let delta_r = Fr::rand(&mut rng);
        let rerandomized_commitment =
            commitment.rerandomize(&ps_scheme.commitment_scheme.ck, delta_r);
        let signature_rerandomized = ps_scheme.sign(&rerandomized_commitment);
        assert!(
            ps_scheme.verify(&signature_rerandomized, &rerandomized_commitment),
            "Signature verification failed for rerandomized commitment"
        );

        // Test 4: Different signers produce different signatures
        let ps_scheme2 = PSSignatureScheme::<E>::setup(m_count, &mut rng);
        let signature2 = ps_scheme2.sign(&commitment);
        assert_ne!(
            signature.sigma1, signature2.sigma1,
            "Different signers should produce different signatures"
        );
    }
}

// pub struct PublicParams<E: Pairing> {
//     pub ck: CommitmentKey<E>,
//     pub vk: E::G2Affine,
// }

// impl<E: Pairing> CommitmentKey<E> {
//     fn get_components(
//         &self,
//     ) -> (
//         &Vec<E::G1Affine>,
//         &E::G1Affine,
//         &Vec<E::G2Affine>,
//         &E::G2Affine,
//     ) {
//         (&self.g1_y, &self.h1, &self.g2_y, &self.h2)
//     }
// }

// pub struct SignerKey<E: Pairing> {
//     pub sk: E::G1Affine,
// }

// impl<E: Pairing> PublicParams<E> {
//     pub fn new<R: Rng>(m_count: &usize, rng: &mut R) -> (Self, SignerKey<E>) {
//         let h1 = E::G1Affine::rand(rng);
//         let h2 = E::G2Affine::rand(rng);

//         let yi: Vec<E::ScalarField> = (0..*m_count).map(|_| E::ScalarField::rand(rng)).collect();

//         let g1_y_proj: Vec<E::G1> = yi.iter().map(|yi| h1.mul(*yi)).collect();
//         let g1_y = E::G1::normalize_batch(&g1_y_proj);

//         let g2_y_proj: Vec<E::G2> = yi.iter().map(|yi| h2.mul(*yi)).collect();
//         let g2_y = E::G2::normalize_batch(&g2_y_proj);

//         // generate secret x
//         let x = E::ScalarField::rand(rng);
//         let sk = h1.mul(x).into_affine();
//         let vk = h2.mul(x).into_affine();

//         let signer_key = SignerKey { sk };

//         let public_params = PublicParams {
//             ck: CommitmentKey { h1, h2, g1_y, g2_y },
//             vk,
//         };
//         (public_params, signer_key)
//     }
// }

// impl<E: Pairing> Signature<E> {}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
//     use ark_std::rand::thread_rng;
//     use ark_std::UniformRand;

//     type E = Bls12_381;

//     #[test]
//     fn test_commitment_creation() {
//         let mut rng = thread_rng();

//         // Test with 3 messages
//         let m_count = 3;
//         let (params, _signer_key) = PublicParams::<E>::new(&m_count, &mut rng);

//         // Create random messages
//         let messages: Vec<Fr> = (0..m_count).map(|_| Fr::rand(&mut rng)).collect();

//         // Create random randomness
//         let r = Fr::rand(&mut rng);

//         // Create commitment
//         let commitment = Commitment::<E>::new(messages.clone(), r, &params.ck);

//         // Verify commitment properties
//         assert_eq!(commitment.m.len(), m_count, "Message count mismatch");
//         assert_eq!(commitment.m, messages, "Stored messages don't match input");
//         assert_eq!(commitment.r, r, "Stored randomness doesn't match input");

//         // Verify commitment components are not identity
//         assert!(!commitment.g1_cm.is_zero(), "G1 commitment is zero");
//         assert!(!commitment.g2_cm.is_zero(), "G2 commitment is zero");

//         // Verify commitment consistency
//         let (g1_y, h1, g2_y, h2) = params.ck.get_components();

//         // Manually compute commitments
//         let manual_g1_cm = Helpers::commit_g1::<E>(&r, &messages, g1_y, h1);
//         let manual_g2_cm = Helpers::commit_g2::<E>(&r, &messages, g2_y, h2);

//         assert_eq!(commitment.g1_cm, manual_g1_cm, "G1 commitment mismatch");
//         assert_eq!(commitment.g2_cm, manual_g2_cm, "G2 commitment mismatch");

//         let delta_r = Fr::rand(&mut rng);
//         let g1_manual_randomized_com = commitment.g1_cm.add(commitment.ck.h1.mul(delta_r));
//         let g1_randomized_com = commitment.rerandomize(delta_r).g1_cm;
//         assert_eq!(
//             g1_manual_randomized_com, g1_randomized_com,
//             "randomized not working"
//         );
//     }

//     #[test]
//     fn test_commitment_key_components() {
//         let mut rng = thread_rng();
//         let m_count = 5;
//         let (params, _) = PublicParams::<E>::new(&m_count, &mut rng);

//         let (g1_y, h1, g2_y, h2) = params.ck.get_components();

//         // Verify component lengths
//         assert_eq!(g1_y.len(), m_count, "G1 vector length mismatch");
//         assert_eq!(g2_y.len(), m_count, "G2 vector length mismatch");

//         // Verify components are not identity
//         assert!(!h1.is_zero(), "h1 is zero");
//         assert!(!h2.is_zero(), "h2 is zero");

//         for (i, (g1, g2)) in g1_y.iter().zip(g2_y.iter()).enumerate() {
//             assert!(!g1.is_zero(), "G1 component {} is zero", i);
//             assert!(!g2.is_zero(), "G2 component {} is zero", i);
//         }
//     }
// }
