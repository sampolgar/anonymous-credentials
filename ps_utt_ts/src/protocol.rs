// pub fn setup(t: usize, n: usize, l: usize, rng: &mut impl Rng) -> ProtocolSetup<E> { ... }

// pub fn execute_protocol(
//     setup: &ProtocolSetup<E>,
//     message: &E::ScalarField,
//     signers: &[usize], // Which signers to use
//     rng: &mut impl Rng
// ) -> Result<BlindSignature<E>, ThresholdSignatureError> { ... }
