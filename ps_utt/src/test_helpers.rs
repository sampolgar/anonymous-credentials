use crate::commitment::Commitment;
use crate::keygen::{
    gen_keys, gen_keys_improved, SecretKey, SecretKeyImproved, VerificationKey,
    VerificationKeyImproved,
};
use crate::publicparams::PublicParams;
use crate::signature::{PSUTTSignature, PSUTTSignatureImproved};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

pub struct PSUttTestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub sk: SecretKey<E>,
    pub vk: VerificationKey<E>,
    pub commitment: Commitment<E>,
    pub signature: PSUTTSignature<E>,
}

impl<E: Pairing> PSUttTestSetup<E> {
    pub fn new(msg_count: usize, user_id: &E::ScalarField) -> Self {
        let mut rng = ark_std::test_rng();
        let context = E::ScalarField::rand(&mut rng);

        let mut messages: Vec<_> = (0..msg_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        messages[0] = *user_id;

        let r = E::ScalarField::rand(&mut rng);

        let pp = PublicParams::<E>::new(&msg_count, &context, &mut rng);
        let (sk, vk) = gen_keys(&pp, &mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);
        let signature = PSUTTSignature::sign(&pp, &sk, &commitment.cmg1, &mut rng);

        assert!(
            signature.verify(&pp, &vk, &commitment.cmg1, &commitment.cmg2),
            "sig isn't valid"
        );

        Self {
            pp,
            sk,
            vk,
            commitment,
            signature,
        }
    }
}

pub struct PSUttImprovedTestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub sk: SecretKeyImproved<E>,
    pub vk: VerificationKeyImproved<E>,
    pub commitment: Commitment<E>,
    pub signature: PSUTTSignatureImproved<E>,
}

impl<E: Pairing> PSUttImprovedTestSetup<E> {
    pub fn new(msg_count: usize, user_id: &E::ScalarField) -> Self {
        let mut rng = ark_std::test_rng();
        let context = E::ScalarField::rand(&mut rng);

        let mut messages: Vec<_> = (0..msg_count)
            .map(|_| E::ScalarField::rand(&mut rng))
            .collect();
        messages[0] = *user_id;

        let r = E::ScalarField::rand(&mut rng);

        let pp = PublicParams::<E>::new(&msg_count, &context, &mut rng);
        let (sk, vk) = gen_keys_improved(&pp, &mut rng);
        let commitment = Commitment::new(&pp, &messages, &r);
        let signature = PSUTTSignatureImproved::sign(&pp, &sk, &commitment.cmg2, &mut rng);

        assert!(
            signature.verify(&pp, &vk, &commitment.cmg1),
            "sig isn't valid"
        );

        Self {
            pp,
            sk,
            vk,
            commitment,
            signature,
        }
    }
}
