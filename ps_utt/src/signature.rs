use crate::commitment::Commitment;
use crate::keygen::KeyPair;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul, Neg},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;
use utils::pairing::PairingCheck;

#[derive(Clone, Debug)]
pub struct PSSignature<E: Pairing> {
    pub sigma1: E::G1Affine,
    pub sigma2: E::G1Affine,
}

impl<E: Pairing> PSSignature<E> {
    pub fn sign(
        pp: &PublicParams<E>,
        keypair: &KeyPair<E>,
        commitment: &Commitment<E>,
        rng: &mut impl Rng,
    ) -> Self {
        let u = E::ScalarField::rand(rng);
        let sigma1 = pp.g1.mul(u).into_affine();
        let sigma2 = (commitment.cmg1.add(keypair.sk)).mul(u).into_affine();
        Self { sigma1, sigma2 }
    }

    // pub fn blind_sign

    pub fn rerandomize(
        &self,
        pp: &PublicParams<E>,
        r_delta: &E::ScalarField,
        u_delta: &E::ScalarField,
    ) -> Self {
        let sigma1_prime = self.sigma1.mul(u_delta).into_affine();
        let temp = self.sigma1.mul(r_delta);
        let sigma2_prime = (temp.add(self.sigma2)).mul(u_delta).into_affine();
        Self {
            sigma1: sigma1_prime,
            sigma2: sigma2_prime,
        }
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        keypair: &KeyPair<E>,
        commitment: &Commitment<E>,
    ) -> bool {
        // verify e(sigma2, g2) = e(sigma1, vk \cdot cm)
        let p1 = E::pairing(self.sigma2, pp.g2);
        let p2 = E::pairing(self.sigma1, keypair.vk.add(commitment.cmg2));
        let is_valid = p1 == p2;
        assert_eq!(p1, p2);
        let cmg1 = commitment.cmg1;
        let cmg2 = commitment.cmg2;
        let p3 = E::pairing(cmg1, pp.g2);
        let p4 = E::pairing(pp.g1, cmg2);
        assert_eq!(p3, p4);
        return is_valid;
    }

    // we change our 2 pairing checks
    //  e(sigma2, \tilde{g2}) = e(sigma1, \tilde{vk} \cdot \tilde{cm})
    //  e(cm, \tilde{g}) = e(g1, \tilde{cm})
    // to
    // e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
    // e(cmg1, g2) * e(g1, cmg2)^-1 = 1
    // and merge
    // e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 * e(cmg1, g2) * e(g1, cmg2)^-1 = 1
    pub fn verify_with_pairing_checker(
        &self,
        pp: &PublicParams<E>,
        keypair: &KeyPair<E>,
        commitment: &Commitment<E>,
    ) -> bool {
        let mut rng = ark_std::test_rng();
        let mr = std::sync::Mutex::new(rng);

        // First equation: e(sigma2, g2) = e(sigma1, vk + cmg2)
        // Rearrange to: e(sigma2, g2) * e(sigma1, vk + cmg2)^-1 = 1
        let vk_plus_cmg2 = keypair.vk.add(commitment.cmg2).into_affine();

        let check1 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&self.sigma2, &pp.g2),
                (&self.sigma1.into_group().neg().into_affine(), &vk_plus_cmg2),
            ],
            &E::TargetField::one(),
        );

        // Second equation: e(cmg1, g2) = e(g1, cmg2)
        // Rearrange to: e(cmg1, g2) * e(g1, cmg2)^-1 = 1
        let check2 = PairingCheck::<E>::rand(
            &mr,
            &[
                (&commitment.cmg1, &pp.g2),
                (&pp.g1.into_group().neg().into_affine(), &commitment.cmg2),
            ],
            &E::TargetField::one(),
        );

        let mut final_check = PairingCheck::<E>::new();
        final_check.merge(&check1);
        final_check.merge(&check2);
        final_check.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_randomized_signature() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let keypair = KeyPair::new(&pp, &mut rng);
        let messages = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);

        let sig = PSSignature::sign(&pp, &keypair, &commitment, &mut rng);
        let is_valid = sig.verify(&pp, &keypair, &commitment);
        assert!(is_valid);

        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_sig = sig.rerandomize(&pp, &r_delta, &u_delta);

        let is_randomized_valid = randomized_sig.verify(&pp, &keypair, &randomized_commitment);
        assert!(is_randomized_valid, "randomized sig verification failed");
    }

    #[test]
    fn test_randomized_signature_pairing_checker() {
        let mut rng = ark_std::test_rng();
        let context = Fr::rand(&mut rng);
        let pp = PublicParams::<Bls12_381>::new(&4, &context, &mut rng);
        let keypair = KeyPair::new(&pp, &mut rng);
        let messages = (0..pp.n).map(|_| Fr::rand(&mut rng)).collect();
        let r = Fr::rand(&mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);

        let sig = PSSignature::sign(&pp, &keypair, &commitment, &mut rng);
        let is_valid = sig.verify(&pp, &keypair, &commitment);
        assert!(is_valid);

        let u_delta = Fr::rand(&mut rng);
        let r_delta = Fr::rand(&mut rng);
        let randomized_commitment = commitment.create_randomized(&r_delta);
        let randomized_sig = sig.rerandomize(&pp, &r_delta, &u_delta);

        let is_randomized_valid = randomized_sig.verify(&pp, &keypair, &randomized_commitment);
        assert!(is_randomized_valid, "randomized sig verification failed");
    }
}
