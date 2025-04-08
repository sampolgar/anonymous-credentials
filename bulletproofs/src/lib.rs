#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_snake_case)]

pub mod aliases;
pub mod error;
pub mod ff;
pub mod hashing_utils;
pub mod msm;
pub mod range_proof;
pub mod range_proof_arbitrary_range;
pub mod serde_utils;
pub mod setup;
pub mod transcript;
pub mod util;
pub mod weighted_norm_linear_argument;

pub mod prelude {
    pub use crate::{
        error::BulletproofsPlusPlusError,
        range_proof::{Proof, Prover},
        range_proof_arbitrary_range::ProofArbitraryRange,
        setup::SetupParams,
    };
}

/// Concatenates supplied slices into one continuous vector.
#[macro_export]
macro_rules! concat_slices {
    ($($slice: expr),+) => {
        [$(&$slice[..]),+].concat()
    }
}
