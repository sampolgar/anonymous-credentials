// use ark_ec::pairing::Pairing;
// use ark_ff::UniformRand;
// use ark_std::rand::Rng;

// #[derive(Clone)]
// pub struct PublicParams<E: Pairing> {
//     pub context: E::ScalarField,
//     pub g: E::G1Affine,
//     pub g_tilde: E::G2Affine,
// }

// impl<E: Pairing> PublicParams<E> {
//     pub fn new(context: &E::ScalarField, rng: &mut impl Rng) -> Self {
//         // let scalar = E::ScalarField::rand(rng);
//         // let g1 = E::G1Affine::generator().mul(scalar).into_affine();
//         // let g2 = E::G2Affine::generator().mul(scalar).into_affine();
//         let g = E::G1Affine::rand(rng);
//         let g_tilde = E::G2Affine::rand(rng);
//         PublicParams {
//             context: *context,
//             g,
//             g_tilde,
//         }
//     }
// }
