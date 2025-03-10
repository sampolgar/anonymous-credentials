├── ps_utt_ts
│ ├── src/
│ │ ├── lib.rs # Main exports and documentation
│ │ ├── commitment.rs # Commitment schemes
│ │ ├── shamir.rs # Secret sharing (from dkg_shamir.rs)
│ │ ├── keygen.rs # Key generation (from dkg_keygen.rs)
│ │ ├── signature.rs # Core signature operations (from signature_ts.rs)
│ │ ├── signer.rs # Complete signer implementation
│ │ ├── credential.rs # User credential operations
│ │ ├── verification.rs # Complete verification implementation
│ │ └── protocol.rs # High-level protocol orchestration
│ └── Cargo.toml
