use crate::{keygen, signature};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
};
use schnorr::schnorr::SchnorrProtocol;
use schnorr::schnorr_pairing::SchnorrProtocolPairing;
use signature::Signature;
use utils::helpers::Helpers;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

#[cfg(feature = "parallel")]
#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, G2Projective};
    use ark_bls12_381::{Config as Bls12_381Config, Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::CyclotomicMultSubgroup;
    use ark_std::test_rng;

    #[test]
    fn test_multiattribute_ps() {
        // setup / keygen
        //
        let message_count = 6;
        let mut rng = ark_std::test_rng();
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.sk;
        let pk = key_pair.pk;

        // Create user's messages
        let messages: Vec<Fr> = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        // Multi-Message Protocol, 6.1
        // generate a commitment, prove knowledge, select random t
        let t = Fr::rand(&mut rng);
        let signature_commitment =
            Helpers::compute_commitment_g1::<Bls12_381>(&t, &pk.g1, &messages, &pk.y_g1);

        // create fake challenge
        let exponents = Helpers::add_scalar_to_vector::<Bls12_381>(&t, &messages);
        let bases = Helpers::add_affine_to_vector::<G1Projective>(&pk.g1, &pk.y_g1);

        // Prove Knowledge Of Opening of the Commitment
        let com_prime = SchnorrProtocol::commit(&bases, &mut rng);
        let challenge = Fr::rand(&mut rng);
        let response = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &signature_commitment,
            &com_prime,
            &response,
            &challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");

        //
        // If the signer is convinced, she signs
        //
        let blind_signature =
            Signature::<Bls12_381>::blind_sign(&pk, &sk, &signature_commitment, &mut rng);

        // user
        let unblinded_signature = blind_signature.unblind(&t);

        // sanity check with verifying the unblinded signature in the clear
        let is_valid = unblinded_signature.public_verify(&messages, &pk);
        assert!(is_valid, "Public signature verification failed");

        // Signature of Knowledge
        //
        let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let tt = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let sigma_prime = unblinded_signature.randomize_for_pok(&r, &tt);
        let sigma_prime_1 = sigma_prime.sigma1;
        let sigma_prime_2 = sigma_prime.sigma2;

        // generate a commitment to the signature
        // e(sigma2p, pk.g2) * e(sigma1p, -pk.xg2)
        let signature_commitment_gt = Helpers::compute_gt::<Bls12_381>(
            &[
                sigma_prime_2,
                sigma_prime_1.into_group().neg().into_affine(),
            ],
            &[pk.g2, pk.x_g2],
        );

        // generate commitment to secret exponents tt, m1, ... ,mn
        let base_length = message_count + 1;
        let bases_g1 = Helpers::copy_point_to_length_g1::<Bls12_381>(sigma_prime_1, &base_length);
        let bases_g2 = Helpers::add_affine_to_vector::<G2Projective>(&pk.g2, &pk.y_g2);

        // generate proving commitment
        let schnorr_commitment_gt =
            SchnorrProtocolPairing::commit::<Bls12_381, _>(&bases_g1, &bases_g2, &mut rng);

        let challenge2 = Fr::rand(&mut rng);

        // gen vector [tt, m1, m2, m....
        let m_vector = Helpers::add_scalar_to_vector::<Bls12_381>(&tt, &messages);
        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &m_vector, &challenge2);

        let isvalid = SchnorrProtocolPairing::verify(
            &schnorr_commitment_gt.t_com,
            &signature_commitment_gt,
            &challenge2,
            &bases_g1,
            &bases_g2,
            &responses.0,
        );

        assert!(isvalid, "pairing not valid");
    }

    fn test_multiattribute_selectivedisclosure_ps() {
        // setup / keygen
        //
        let message_count = 6;
        let mut rng = ark_std::test_rng();
        let key_pair = keygen::keygen::<Bls12_381, _>(&mut rng, &message_count);
        let sk = key_pair.sk;
        let pk = key_pair.pk;

        // Create user's messages
        let messages: Vec<Fr> = (0..message_count)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        // Multi-Message Protocol, 6.1
        // generate a commitment, prove knowledge, select random t
        let t = Fr::rand(&mut rng);
        let signature_commitment =
            Helpers::compute_commitment_g1::<Bls12_381>(&t, &pk.g1, &messages, &pk.y_g1);

        // create fake challenge
        let exponents = Helpers::add_scalar_to_vector::<Bls12_381>(&t, &messages);
        let bases = Helpers::add_affine_to_vector::<G1Projective>(&pk.g1, &pk.y_g1);

        // Prove Knowledge Of Opening of the Commitment
        let com_prime = SchnorrProtocol::commit(&bases, &mut rng);
        let challenge = Fr::rand(&mut rng);
        let response = SchnorrProtocol::prove(&com_prime, &exponents, &challenge);
        let is_valid = SchnorrProtocol::verify(
            &bases,
            &signature_commitment,
            &com_prime,
            &response,
            &challenge,
        );

        assert!(is_valid, "Schnorr proof verification failed");

        //
        // If the signer is convinced, she signs
        //
        let blind_signature =
            Signature::<Bls12_381>::blind_sign(&pk, &sk, &signature_commitment, &mut rng);

        // user
        let unblinded_signature = blind_signature.unblind(&t);

        // sanity check with verifying the unblinded signature in the clear
        let is_valid = unblinded_signature.public_verify(&messages, &pk);
        assert!(is_valid, "Public signature verification failed");

        // Signature of Knowledge
        //
        let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let tt = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
        let sigma_prime = unblinded_signature.randomize_for_pok(&r, &tt);
        let sigma_prime_1 = sigma_prime.sigma1;
        let sigma_prime_2 = sigma_prime.sigma2;

        // generate a commitment to the signature
        // e(sigma2p, pk.g2) * e(sigma1p, -pk.xg2)
        let signature_commitment_gt = Helpers::compute_gt::<Bls12_381>(
            &[
                sigma_prime_2,
                sigma_prime_1.into_group().neg().into_affine(),
            ],
            &[pk.g2, pk.x_g2],
        );

        // generate commitment to secret exponents tt, m1, ... ,mn
        let base_length = message_count + 1;
        let bases_g1 = Helpers::copy_point_to_length_g1::<Bls12_381>(sigma_prime_1, &base_length);
        let bases_g2 = Helpers::add_affine_to_vector::<G2Projective>(&pk.g2, &pk.y_g2);

        // generate proving commitment
        let schnorr_commitment_gt =
            SchnorrProtocolPairing::commit::<Bls12_381, _>(&bases_g1, &bases_g2, &mut rng);

        let challenge2 = Fr::rand(&mut rng);

        // gen vector [tt, m1, m2, m....
        let m_vector = Helpers::add_scalar_to_vector::<Bls12_381>(&tt, &messages);
        let responses =
            SchnorrProtocolPairing::prove(&schnorr_commitment_gt, &m_vector, &challenge2);

        let isvalid = SchnorrProtocolPairing::verify(
            &schnorr_commitment_gt.t_com,
            &signature_commitment_gt,
            &challenge2,
            &bases_g1,
            &bases_g2,
            &responses.0,
        );

        assert!(isvalid, "pairing not valid");
    }
}
