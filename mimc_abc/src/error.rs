use thiserror::Error;

/// Possible errors that can occur during commitment proof operations
#[derive(Error, Debug)]
pub enum CommitmentError {
    /// The commitment is invalid
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Invalid index for equality proof")]
    InvalidEqualityIndex,
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
