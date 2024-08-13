use crate::{keygen, signature::Signature};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

pub struct PSTestSetup<E: Pairing> {
    pub pk: keygen::PublicKey<E>,
    pub sk: keygen::SecretKey<E>,
    pub messages: Vec<E::ScalarField>,
    pub signature: Signature<E>,
}

pub fn create_ps_test_setup<E: Pairing>(message_count: usize) -> PSTestSetup<E> {
    let mut rng = ark_std::test_rng();
    let key_pair = keygen::keygen::<E, _>(&mut rng, &message_count);
    let messages: Vec<E::ScalarField> = (0..message_count)
        .map(|_| E::ScalarField::rand(&mut rng))
        .collect();

    // Create a signature commitment
    let t = E::ScalarField::rand(&mut rng);
    let signature_commitment = utils::helpers::Helpers::compute_commitment_g1::<E>(
        &t,
        &key_pair.pk.g1,
        &messages,
        &key_pair.pk.y_g1,
    );

    // Create a blind signature
    let blind_signature =
        Signature::blind_sign(&key_pair.pk, &key_pair.sk, &signature_commitment, &mut rng);
    let signature = blind_signature.unblind(&t);

    PSTestSetup {
        pk: key_pair.pk,
        sk: key_pair.sk,
        messages,
        signature,
    }
}
