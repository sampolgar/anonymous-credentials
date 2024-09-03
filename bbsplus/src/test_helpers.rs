use crate::{
    keygen,
    signature::{self, RandomizedSignature, Signature},
};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;

pub struct BBSPlusTestSetup<E: Pairing> {
    pub pk: keygen::PublicKey<E>,
    pub sk: keygen::SecretKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub signature: Signature<E>,
    pub blind_signature: RandomizedSignature<E>,
}

pub fn create_bbs_plus_test_setup<E: Pairing>(message_count: usize) -> BBSPlusTestSetup<E> {
    let mut rng = ark_std::test_rng();
    let key_pair = keygen::keygen::<E, _>(&mut rng, &message_count);
    let pk = key_pair.public_key().clone();
    let sk = key_pair.secret_key().clone();
    let messages: Vec<E::ScalarField> = (0..message_count)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect();
    let signature = Signature::<E>::sign(&pk, &sk, &messages, &mut rng);
    let blind_signature = signature.randomize(&pk, &mut rng, &messages);

    BBSPlusTestSetup {
        pk,
        sk,
        messages,
        signature,
        blind_signature,
    }
}
