# Anonymous Credentials

This project will evaluate Threshold BBS+ and Threshold PS (Coconut) with respect to proof and verify times using shared components to fairly compare schemes.

I credit Lovesh Harchandani https://github.com/lovesh for his work on anonymous credentials as I've taken much inspiration from it

Todo

- [ ] Remove println and clean up
- [ ] Update pairing to faster pairing function
- [ ] Do Equality Proofs with multiple credentials

Notes
cargo bench

Problems found

- bbsplus has to be remade to support proving from multiple credentials as per https://github.com/sampolgar/dock-crypto/blob/main/bbs_plus/src/proof_23.rs
