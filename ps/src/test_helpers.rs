// use crate::{keygen, signature::Signature};
// use ark_ec::pairing::Pairing;
// use ark_ff::UniformRand;

// // these make it much easier to test
// pub struct PSTestSetup<E: Pairing> {
//     pub pk: keygen::PublicKey<E>,
//     pub sk: keygen::SecretKey<E>,
//     pub messages: Vec<E::ScalarField>,
//     pub signature: Signature<E>,
// }

// pub fn create_ps_test_setup<E: Pairing>(message_count: usize) -> PSTestSetup<E> {
//     let mut rng = ark_std::test_rng();
//     let key_pair = keygen::keygen::<E, _>(&mut rng, &message_count);
//     let messages: Vec<E::ScalarField> = (0..message_count)
//         .map(|_| E::ScalarField::rand(&mut rng))
//         .collect();

//     // Create a signature commitment
//     let t = E::ScalarField::rand(&mut rng);
//     let signature_commitment = utils::helpers::Helpers::compute_commitment_g1::<E>(
//         &t,
//         &key_pair.pk.g1,
//         &messages,
//         &key_pair.pk.y_g1,
//     );

//     // Create a blind signature
//     let blind_signature =
//         Signature::blind_sign(&key_pair.pk, &key_pair.sk, &signature_commitment, &mut rng);
//     let signature = blind_signature.unblind(&t);

//     PSTestSetup {
//         pk: key_pair.pk,
//         sk: key_pair.sk,
//         messages,
//         signature,
//     }
// }

// // set user_id as position 0 in the message vector
// pub fn create_ps_with_userid<E: Pairing>(
//     message_count: usize,
//     user_id: &E::ScalarField,
// ) -> PSTestSetup<E> {
//     let mut rng = ark_std::test_rng();
//     let key_pair = keygen::keygen::<E, _>(&mut rng, &message_count);
//     let mut messages: Vec<E::ScalarField> = (0..message_count)
//         .map(|_| E::ScalarField::rand(&mut rng))
//         .collect();

//     // set position 0 to be user_id
//     messages[0] = *user_id;

//     // Create a signature commitment
//     let t = E::ScalarField::rand(&mut rng);
//     let signature_commitment = utils::helpers::Helpers::compute_commitment_g1::<E>(
//         &t,
//         &key_pair.pk.g1,
//         &messages,
//         &key_pair.pk.y_g1,
//     );

//     // Create a blind signature
//     let blind_signature =
//         Signature::blind_sign(&key_pair.pk, &key_pair.sk, &signature_commitment, &mut rng);
//     let signature = blind_signature.unblind(&t);

//     PSTestSetup {
//         pk: key_pair.pk,
//         sk: key_pair.sk,
//         messages,
//         signature,
//     }
// }

// pub struct BenchmarkSetup<E: Pairing> {
//     pub credentials_count: usize,
//     pub message_count: usize,
//     pub user_id: E::ScalarField,
//     pub user_id_blindness: E::ScalarField,
//     pub challenge: E::ScalarField,
//     pub setups: Vec<PSTestSetup<E>>,
// }

// impl<E: Pairing> BenchmarkSetup<E> {
//     pub fn new(credentials_count: usize, message_count: usize) -> Self {
//         let mut rng = ark_std::test_rng();
//         let user_id = E::ScalarField::rand(&mut rng);
//         let user_id_blindness = E::ScalarField::rand(&mut rng);
//         let challenge = E::ScalarField::rand(&mut rng);

//         let setups = (0..credentials_count)
//             .map(|_| create_ps_with_userid::<E>(message_count, &user_id))
//             .collect();

//         Self {
//             credentials_count,
//             message_count,
//             user_id,
//             user_id_blindness,
//             challenge,
//             setups,
//         }
//     }
// }
