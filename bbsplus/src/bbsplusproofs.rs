use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Neg;
use schnorr::schnorr_pairing::SchnorrProtocolPairing;
use thiserror::Error;
use utils::helpers::Helpers;

pub struct BBSPlusProofs;

// impl BBSPlusProofs {
//     pub fn prove_knowledge<E: Pairing>
// }
