// test_helpers.rs
use crate::keygen::{gen_keys, PublicKey, SecretKey};
use crate::publicparams::PublicParams;
use crate::signature::BBSPlus16Signature;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

pub struct TestSetup<E: Pairing> {
    pub pp: PublicParams<E>,
    pub sk: SecretKey<E>,
    pub pk: PublicKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub signature: BBSPlus16Signature<E>,
}

impl<E: Pairing> TestSetup<E> {
    pub fn new(rng: &mut impl Rng, message_count: usize) -> Self {
        let context = E::ScalarField::rand(rng);
        let pp = PublicParams::<E>::new(&message_count, &context, rng);
        let (sk, pk) = gen_keys::<E>(&pp, rng);

        let messages: Vec<E::ScalarField> = (0..message_count)
            .map(|_| E::ScalarField::rand(rng))
            .collect();

        let signature = BBSPlus16Signature::sign(&pp, &sk, &pk, rng, &messages);

        TestSetup {
            pp,
            sk,
            pk,
            messages,
            signature,
        }
    }
}
