use crate::keygen;
use schnorr::schnorr::SchnorrProtocol;
use schnorr::schnorr_pairing::{SchnorrCommitmentPairing, SchnorrProtocolPairing};
use utils::helpers::Helpers;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

// pub struct SignatureMessages<E: Pairing> {
//     pub messages: Vec<E::ScalarField>,
//     pub t: E::ScalarField,
//     pub tt: E::ScalarField,
// }

impl<E: Pairing> Signature<E> {
    //
    pub fn blind_sign<R: Rng>(
        pk: &keygen::PublicKey<E>,
        sk: &keygen::SecretKey<E>,
        signature_commitment: &E::G1Affine,
        rng: &mut R,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pk.g1.mul(u).into_affine();
        let sigma2 = (pk.g1.mul(sk.x) + signature_commitment)
            .mul(u)
            .into_affine();
        Self { sigma1, sigma2 }
    }

    pub fn unblind(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1,
            sigma2: (self.sigma2.into_group() - self.sigma1.mul(*t)).into_affine(),
        }
    }

    // rerandomize signature by scalar
    pub fn rerandomize(&self, t: &E::ScalarField) -> Self {
        Self {
            sigma1: self.sigma1.mul(t).into_affine(),
            sigma2: self.sigma2.mul(t).into_affine(),
        }
    }

    //
    pub fn randomize_for_pok(&self, r: &E::ScalarField, t: &E::ScalarField) -> Self {
        let sigma1_temp = self.sigma1;
        Self {
            sigma1: self.sigma1.mul(r).into_affine(),
            sigma2: (self.sigma2.into_group() + sigma1_temp.mul(*t))
                .mul(r)
                .into_affine(),
        }
    }

    // this is for testing, public signature isn't used in anonymous credentials
    // this will be used for pairing testing
    pub fn public_sign(
        messages: &[E::ScalarField],
        sk: &keygen::SecretKey<E>,
        h: &E::G1Affine,
    ) -> Self {
        assert!(messages.len() == sk.yi.len());
        let mut exponent = sk.x;
        for (y, m) in sk.yi.iter().zip(messages.iter()) {
            exponent += *y * m;
        }
        let sigma2 = h.mul(exponent).into_affine();
        Self { sigma1: *h, sigma2 }
    }

    pub fn public_verify(&self, messages: &[E::ScalarField], pk: &keygen::PublicKey<E>) -> bool {
        assert!(!self.sigma1.is_zero());
        assert_eq!(pk.y_g1.len(), messages.len());

        let x_g2 = pk.x_g2.into_group();
        let yi = pk.y_g2.clone();
        let yimi = E::G2::msm(&yi, messages).unwrap();
        let yimix = yimi + x_g2;

        let a = E::G1Prepared::from(self.sigma1);
        let b = E::G2Prepared::from(yimix);
        let sigma2_inv = self.sigma2.into_group().neg();
        let c = E::G1Prepared::from(sigma2_inv);
        let d = E::G2Prepared::from(pk.g2);

        let multi_pairing = E::multi_pairing([a, c], [b, d]);
        multi_pairing.0.is_one()
    }

    // /// Process:
    // /// 1. Randomize the signature
    // /// 2. Create Schnorr proof for hidden messages and randomization factor
    // /// 3. Compute signature commitment in GT
    // /// 4. Return proof containing randomized signature, Schnorr proof, and disclosed messages
    // pub fn prove_selective_disclosure<R: Rng>(
    //     &self,
    //     pk: &keygen::PublicKey<E>,
    //     messages: &[E::ScalarField],
    //     disclosed_indices: &[usize],
    //     rng: &mut R,
    // ) -> SelectiveDisclosureProof<E> {
    //     let r = E::ScalarField::rand(rng);
    //     let t = E::ScalarField::rand(rng);
    //     let proof_length = messages.len() - disclosed_indices.len() + 1; //t + m1,m2,.., for hidden messages + t
    //     let randomized_sig = self.randomize_for_pok(&r, &t);

    //     // prepare bases and exponents for proof
    //     let bases_g1_undisclosed =
    //         Helpers::copy_point_to_length_g1::<E>(randomized_sig.sigma1.clone(), &proof_length);
    //     let bases_g2_undisclosed = Helpers::add_affine_to_vector::<E::G2>(&pk.g2, &pk.y_g2);

    //     // add undisclosed exponents to the commitment
    //     let mut exponents = vec![t];
    //     for (i, m) in messages.iter().enumerate() {
    //         if !disclosed_indices.contains(&i) {
    //             exponents.push(*m);
    //         }
    //     }

    //     // generate commitment to the sizesecret exponents tt, m1, ... ,mn
    //     let schnorr_commitment = SchnorrProtocolPairing::commit::<E, _>(
    //         &bases_g1_undisclosed,
    //         &bases_g2_undisclosed,
    //         rng,
    //     );

    //     // generate a commitment to the signature
    //     // e(sigma2p, pk.g2) * e(sigma1p, -pk.xg2)
    //     let signature_commitment = Helpers::compute_gt::<E>(
    //         &[
    //             randomized_sig.sigma2,
    //             randomized_sig.sigma1.into_group().neg().into_affine(),
    //         ],
    //         &[pk.g2, pk.x_g2],
    //     );

    //     SelectiveDisclosureProof {
    //         randomized_sig,
    //         schnorr_commitment,
    //         signature_commitment,
    //         disclosed_indices: disclosed_indices.to_vec(),
    //         disclosed_messages: disclosed_indices.iter().map(|&i| messages[i]).collect(),
    //     }
    // }
}

// pub struct SelectiveDisclosureProof<E: Pairing> {
//     randomized_sig: Signature<E>,
//     schnorr_commitment: SchnorrCommitmentPairing<E>,
//     signature_commitment: PairingOutput<E>,
//     disclosed_indices: Vec<usize>,
//     disclosed_messages: Vec<E::ScalarField>,
// }

/// Verifies the pairing equation for the selective disclosure proof
///
/// Process:
/// 1. Compute LHS: e(σ₂', g₂)
/// 2. Compute RHS: e(σ₁', X) * ∏ᵢ₍ᵈᵢₛcˡₒₛₑᵈ₎ e(σ₁', Yᵢ)^mᵢ
/// 3. Implicitly verify undisclosed messages (handled by Schnorr proof)
/// 4. Check if LHS == RHS
// impl<E: Pairing> SelectiveDisclosureProof<E> {
//     fn verify_signature_commitment(
//         &self,
//         pk: &keygen::PublicKey<E>,
//         challenge: &E::ScalarField,
//     ) -> bool {
//         self.verify_schnorr_proof(pk, challenge) && self.verify_signature_commitment(pk)
//     }

//     fn verify_schnorr_proof(&self, pk: &keygen::PublicKey<E>, challenge: &E::ScalarField) -> bool {
//         // Reconstruct the bases for verification
//         let mut bases_g1 = vec![self.randomized_sig.sigma1]; // For t
//         let mut bases_g2 = vec![pk.g2]; // For t

//         // create e(sigma1p, Yi)^mi for hidden messages
//         for i in 0..pk.y_g2.len() {
//             if !self.disclosed_indices.contains(&i) {
//                 bases_g1.push(self.randomized_sig.sigma1);
//                 bases_g2.push(pk.y_g2[i]);
//             }
//         }

//         SchnorrProtocolPairing::verify(
//             &self.schnorr_commitment.t_com,
//             &self.signature_commitment,
//             challenge,
//             &bases_g1,
//             &bases_g2,
//         )
//     }
// }

#[cfg(feature = "parallel")]
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, G2Projective};
    use ark_bls12_381::{Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
    use ark_std::test_rng;

    #[test]
    fn test_sign_and_verify() {
        let message_count = 4;
        let mut rng = ark_std::test_rng();
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.sk;
        let pk = key_pair.pk;

        // Create messages
        let messages: Vec<Fr> = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let h = G1Affine::rand(&mut rng);
        let public_signature = Signature::<Bls12_381>::public_sign(&messages, &sk, &h);
        let is_valid = public_signature.public_verify(&messages, &pk);
        assert!(is_valid, "Public signature verification failed");
    }
}
