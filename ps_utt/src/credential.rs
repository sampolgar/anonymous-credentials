// Credential has
// Signature, Commitment, Public Params
use crate::commitment::Commitment;
use crate::signature::PSSignature;
use ark_ec::pairing::Pairing;

#[derive(Clone)]
pub struct Credential<E: Pairing> {
    pub commitment: Commitment<E>,
    pub signature: PSSignature<E>,
    pub context: E::ScalarField,
}

// core functionality for a credential
impl<E: Pairing> Credential<E> {
    //
    // pub fn verify(&self) -> bool { ... }
    // pub fn randomize(&self) -> Self { ... }
}
