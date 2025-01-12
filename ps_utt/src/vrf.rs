use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    ops::{Add, Mul, Neg},
    rand::Rng,
    sync::Mutex,
    test_rng, One, UniformRand, Zero,
};
use core::marker::PhantomData;
use schnorr::schnorr::{SchnorrCommitment, SchnorrProtocol, SchnorrResponses};

// #[derive(Clone, Debug)]

// delta
// VRF(x, sk, g1)


