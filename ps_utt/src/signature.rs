use crate::commitment::Commitment;
use crate::keygen::KeyPair;
use crate::publicparams::PublicParams;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use ark_std::{
    ops::{Add, Mul},
    One, Zero,
};
use schnorr::schnorr::SchnorrProtocol;

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
        // assert!(is_valid, "PS Sig pairing doesn't work");
        return is_valid;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};

    #[test]
    fn test_randomized_signature() {
        let mut rng = ark_std::test_rng();
        let pp = PublicParams::<Bls12_381>::new(&4, &mut rng);
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
