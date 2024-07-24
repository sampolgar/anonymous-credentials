# cryptography playground in rust

``
Examples of signature libraries
https://github.com/w3f/bls/blob/master/src/schnorr_pop.rs
https://github.com/mmagician/bls-signatures-arkworks-example/blob/master/src/main.rs

Schnorr pok
https://github.com/docknetwork/crypto/tree/main/schnorr_pok
https://crypto.stanford.edu/cs355/19sp/lec5.pdf

coconut
https://github.com/docknetwork/crypto/tree/main/coconut/src/setup

Randomness
use ark_std::{rand::Rng, One, UniformRand};

pub fn setup_fake_srs<E: Pairing, R: Rng>(rng: &mut R, size: usize) -> GenericSRS<E> {
    let alpha = E::ScalarField::rand(rng);
}


Testing
use rand_core::SeedableRng;
let srs = setup_fake_srs::<Bls12, _>(&mut rng, size);

lhs.0 extracts the TargetField from the PairingOutput<E>,