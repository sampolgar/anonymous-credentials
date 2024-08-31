use crate::{keygen, signature::Signature};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;

// pub struct BBSPlusTestSetup<E: Pairing> {
//     pub pk: keygen::PublicKey<E>,
//     pub sk: keygen::SecretKey<E>,
//     pub messages: Vec<E::ScalarField>,
//     pub signature: Signature<E>,
// }

// pub fn create_bbsplus_test_setup<E: Pairing>(message_count: usize) -> BBSPlusTestSetup<E> {
//     let mut rng = ark_std::test_rng();
//     let key_pair = keygen::keygen::<E, _>(&mut rng, &message_count);
//     let messages: Vec<E::ScalarField> = (0..message_count)
//         .map(|_| E::ScalarField::rand(&mut rng))
//         .collect();
// }
