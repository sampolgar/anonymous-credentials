use crate::credential::CredentialState;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Commitment errors
    #[error("Invalid commitment")]
    InvalidCommitment,
    #[error("Mismatched commitment lengths")]
    MismatchedCommitmentLengths,

    // Proof errors
    #[error("Invalid proof")]
    InvalidProof,
    #[error("Proof verification failed")]
    ProofVerificationFailed,

    // Signature errors
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    // Credential errors
    #[error("Invalid credential state: expected {expected:?}, got {actual:?}")]
    InvalidCredentialState {
        expected: CredentialState,
        actual: CredentialState,
    },
    #[error("Missing signature on credential")]
    MissingSignature,

    // Protocol errors
    #[error("Protocol aborted")]
    ProtocolAborted,

    // Library errors
    #[error("Serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
    #[error("Other error: {0}")]
    Other(String),
}
