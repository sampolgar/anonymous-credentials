// the protocol is run with message count and sets up a user with messages and key
// it has publickey, secretkey, signature, message, proof
// User with messages, randomness
use crate::keygen;
use schnorr::schnorr::SchnorrProtocol;
use schnorr::schnorr_pairing::{SchnorrCommitmentPairing, SchnorrProtocolPairing};
use utils::helpers::Helpers;
use utils::pairing::PairingCheck;
use utils::pairs::PairingUtils;

use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::UniformRand;
use ark_std::{
    ops::{Mul, Neg},
    rand::Rng,
    sync::Mutex,
    One, Zero,
};
use rayon::prelude::*;

