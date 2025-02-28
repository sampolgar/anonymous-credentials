use crate::keygen::{PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    One,
};
use utils::helpers::Helpers;
use utils::pairing::verify_pairing_equation;

#[derive(Clone, Debug)]
pub struct PSSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> PSSignature<E> {
    /// Issues a blind signature on a commitment
    pub fn blind_sign<R: Rng>(
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
        sk: &SecretKey<E>,
        signature_commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        // Generate random u
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g1.mul(u).into_affine();
        // sigma2 = (X1 + commitment)^u where X1 = g1^x
        // let sigma2 = (sk.x_g1 + signature_commitment).mul(u).into_affine();
        let sigma2 = (pp.g1.mul(sk.x) + signature_commitment)
            .mul(u)
            .into_affine();

        Self { sigma1, sigma2 }
    }

    /// Unblinds a blind signature using the blinding factor
    pub fn unblind(&self, t: &E::ScalarField) -> Self {
        let sigma2 = self.sigma1.mul(t).neg() + self.sigma2;
        Self {
            sigma1: self.sigma1,
            sigma2: sigma2.into_affine(),
        }
    }

    /// Randomizes signature for proof of knowledge with explicit randomness
    pub fn rerandomize(&self, r: &E::ScalarField, t: &E::ScalarField) -> Self {
        let sigma1_temp = self.sigma1;
        Self {
            // sigma1' = sigma1 * r
            sigma1: self.sigma1.mul(*r).into_affine(),
            // sigma2' = (sigma2 + sigma1 * t) * r
            sigma2: (self.sigma2.into_group() + sigma1_temp.mul(*t))
                .mul(*r)
                .into_affine(),
        }
    }

    /// Generates a GT element for simplified verification
    /// In Short Randomizable Signatures the pairing verification is:
    /// e(sigma1', X2) · ∏ e(sigma1', Yi)^mi · e(sigma1', g2)^t = e(sigma2', g2)
    /// We simplify by taking leftmost pairing over to RHS:
    /// ∏ e(sigma1', Yi)^mi · e(sigma1', g2)^t = e(sigma2', g2) / e(sigma1', X2)
    pub fn generate_commitment_gt(
        &self,
        pp: &PublicParams<E>,
        pk: &PublicKey<E>,
    ) -> PairingOutput<E> {
        let signature_commitment_gt = Helpers::compute_gt::<E>(
            &[self.sigma2, self.sigma1.into_group().neg().into_affine()],
            &[pp.g2, pk.x_g2],
        );
        signature_commitment_gt
    }

    /// Signs a message vector directly (primarily for testing)
    pub fn public_sign(
        messages: &[E::ScalarField],
        sk: &SecretKey<E>,
        pp: &PublicParams<E>,
    ) -> Self {
        assert!(messages.len() == sk.yi.len());
        let mut rng = ark_std::test_rng();
        let h = E::G1Affine::rand(&mut rng);

        let mut exponent = sk.x;
        for (y, m) in sk.yi.iter().zip(messages.iter()) {
            exponent += *y * m;
        }

        // sigma2 = h^(x + ∑(yi * mi))
        let sigma2 = h.mul(exponent).into_affine();
        Self { sigma1: h, sigma2 }
    }

    /// Verifies a signature on public messages
    pub fn public_verify(
        &self,
        pp: &PublicParams<E>,
        messages: &[E::ScalarField],
        pk: &PublicKey<E>,
    ) -> bool {
        assert!(!self.sigma1.is_zero(), "Signature sigma1 cannot be zero");
        assert_eq!(
            pk.y_g2.len(),
            messages.len(),
            "Message count must match public key count"
        );

        // Compute X̃ · ∏ Ỹⱼᵐʲ in G2
        let mut yimix = pk.x_g2.into_group();
        for (yi, mi) in pk.y_g2.iter().zip(messages.iter()) {
            yimix += yi.mul(*mi);
        }

        let x_g2 = pk.x_g2.into_group();
        let yi = pk.y_g2.clone();
        let yimi = E::G2::msm(&yi, messages).unwrap();
        let yimix = yimi + x_g2;
        let sigma2_inv = self.sigma2.into_group().neg();

        verify_pairing_equation::<E>(
            &[
                (&self.sigma1, &yimix.into_affine()),
                (&sigma2_inv.into_affine(), &pp.g2),
            ],
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{compute_commitment_g1, Commitment};
    use crate::keygen::gen_keys;
    use crate::publicparams::PublicParams;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::Zero;

    #[test]
    fn test_ps_signature_direct() {
        // Setup with precisely 5 messages
        let message_count = 5;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Generate exactly 5 random messages
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        // Create signature directly using public_sign
        let signature = Signature::public_sign(&messages, &sk, &pp);

        // Examine the signature components
        println!("Signature created with random generator in G1");

        // Verify signature validity using the bilinear map relation
        let is_valid = signature.public_verify(&pp, &messages, &pk);

        // Assertion with detailed failure message
        assert!(
            is_valid,
            "Signature verification failed. This suggests an inconsistency in the \
         implementation of the bilinear pairing relation e(σ₁, X·∏Yⱼᵐʲ) = e(σ₂, g₂)"
        );

        // Optional: Demonstrate that verification is sensitive to message integrity
        let mut modified_messages = messages.clone();
        modified_messages[2] = Fr::rand(&mut rng); // Modify the third message

        let is_invalid = signature.public_verify(&pp, &modified_messages, &pk);
        assert!(
            !is_invalid,
            "Signature incorrectly verified against modified messages, indicating a \
         fundamental flaw in the verification equation implementation"
        );
    }

    #[test]
    fn test_blind_sign_and_unblind() {
        // Setup
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create messages and commitment
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();
        let t = Fr::rand(&mut rng);

        let commitment = compute_commitment_g1::<Bls12_381>(&t, &pp.g1, &messages, &pk.y_g1);

        // Blind sign
        let blind_signature = Signature::blind_sign(&pp, &pk, &sk, &commitment, &mut rng);
        assert!(
            !blind_signature.sigma1.is_zero(),
            "sigma1 should not be zero"
        );
        assert!(
            !blind_signature.sigma2.is_zero(),
            "sigma2 should not be zero"
        );

        // Unblind
        let signature = blind_signature.unblind(&t);

        // Verify
        let is_valid = signature.public_verify(&pp, &messages, &pk);
        assert!(is_valid, "Unblinded signature verification failed");
    }

    #[test]
    fn test_signature_rerandomization() {
        // Setup
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create messages
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        // Public sign for testing
        let signature = Signature::public_sign(&messages, &sk, &pp);
        assert!(
            signature.public_verify(&pp, &messages, &pk),
            "Original signature should verify"
        );

        // Rerandomize
        let r = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);
        let randomized_signature = signature.rerandomize(&r, &t);
    }

    #[test]
    fn test_randomize_for_pok() {
        // Setup
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create messages
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        // Public sign
        let signature = Signature::public_sign(&messages, &sk, &pp);

        // // Randomize for POK
        let r = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);
        // let randomized = signature.randomize(&r, &t);

        // Test the auto-randomization version too
        let randomized_auto = signature.rerandomize(&r, &t);
        assert!(
            !randomized_auto.sigma1.is_zero(),
            "Auto-randomized sigma1 should not be zero"
        );
        assert!(
            !randomized_auto.sigma2.is_zero(),
            "Auto-randomized sigma2 should not be zero"
        );
    }

    #[test]
    fn test_generate_commitment_gt() {
        // Setup
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create messages
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        // Public sign
        let signature = Signature::public_sign(&messages, &sk, &pp);

        // Generate GT commitment
        let gt_commitment = signature.generate_commitment_gt(&pp, &pk);
        assert!(!gt_commitment.is_zero(), "GT commitment should not be zero");
    }

    #[test]
    fn test_pairing_check_verification() {
        // Setup
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&message_count, &context, &mut rng);
        let (sk, pk) = gen_keys(&pp, &mut rng);

        // Create messages
        let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(&mut rng)).collect();

        // Public sign
        let signature = Signature::public_sign(&messages, &sk, &pp);

        // Verify with standard method
        let is_valid_standard = signature.public_verify(&pp, &messages, &pk);
        assert!(is_valid_standard, "Standard verification failed");
    }
}
