use crate::test_helpers::{PSUttImprovedTestSetup, PSUttTestSetup};
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

pub struct BenchmarkSetup<E: Pairing> {
    pub credentials_count: usize,
    pub message_count: usize,
    pub user_id: E::ScalarField,
    pub user_id_blindness: E::ScalarField,
    pub challenge: E::ScalarField,
    pub psutt_setups: Vec<PSUttTestSetup<E>>,
}

impl<E: Pairing> BenchmarkSetup<E> {
    pub fn new(credentials_count: usize, message_count: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let user_id = E::ScalarField::rand(&mut rng);
        let user_id_blindness = E::ScalarField::rand(&mut rng);
        let challenge = E::ScalarField::rand(&mut rng);

        let psutt_setups = (0..credentials_count)
            .map(|_| PSUttTestSetup::new(message_count, &user_id))
            .collect();

        Self {
            credentials_count,
            message_count,
            user_id,
            user_id_blindness,
            challenge,
            psutt_setups,
        }
    }
}

pub struct BenchmarkSetupImproved<E: Pairing> {
    pub credentials_count: usize,
    pub message_count: usize,
    pub user_id: E::ScalarField,
    pub user_id_blindness: E::ScalarField,
    pub challenge: E::ScalarField,
    pub psutt_setups: Vec<PSUttImprovedTestSetup<E>>,
}

impl<E: Pairing> BenchmarkSetupImproved<E> {
    pub fn new(credentials_count: usize, message_count: usize) -> Self {
        let mut rng = ark_std::test_rng();
        let user_id = E::ScalarField::rand(&mut rng);
        let user_id_blindness = E::ScalarField::rand(&mut rng);
        let challenge = E::ScalarField::rand(&mut rng);

        let psutt_setups = (0..credentials_count)
            .map(|_| PSUttImprovedTestSetup::new(message_count, &user_id))
            .collect();

        Self {
            credentials_count,
            message_count,
            user_id,
            user_id_blindness,
            challenge,
            psutt_setups,
        }
    }
}
