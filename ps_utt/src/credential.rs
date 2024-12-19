// Credential has
// Signature, Commitment, Public Params
use crate::commitment::Commitment;
use crate::publicparams::PublicParams;
use crate::signature::PSSignature;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;

#[derive(Clone)]
pub struct Credential<E: Pairing> {
    pub commitment: Commitment<E>,
    pub signature: PSSignature<E>,
    pub context: E::ScalarField,
}

// Cred = signed Com([s, context, {m}_i],r), s is in each credential
impl<E: Pairing> Credential<E> {
    pub fn new(
        pp: &PublicParams<E>,
        messages: Vec<E::ScalarField>,
        context: E::ScalarField,
    ) -> Self {
        // 
    }
}
