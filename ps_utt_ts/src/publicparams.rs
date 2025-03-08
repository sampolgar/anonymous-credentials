use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::rand::Rng;

#[derive(Clone)]
pub struct PublicParams<E: Pairing> {
    pub context: E::ScalarField,
    pub g: E::G1Affine,
    pub g_tilde: E::G2Affine,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new(context: Option<&E::ScalarField>, rng: &mut impl Rng) -> Self {
        let g = E::G1Affine::rand(rng);
        let g_tilde = E::G2Affine::rand(rng);

        let context = match context {
            Some(ctx) => *ctx,
            None => E::ScalarField::rand(rng),
        };

        PublicParams {
            context,
            g,
            g_tilde,
        }
    }
}
