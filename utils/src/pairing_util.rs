// use ark_ec::pairing::Pairing;
// use ark_ec::{AffineRepr, CurveGroup};
// use ark_std::vec::Vec;

// // takes in vectors of G1, G2, witnesses, returns a vector of tuples [(G1[0]*w[0], G2[0]),...] for pairing
// #[derive(Clone, Debug)]
// pub struct PairingTuple<E: Pairing> {
//     pub pairing_vec: Vec<(E::G1Affine, E::G2Affine)>,
// }

// impl<E> PairingTuple<E>
// where
//     E: Pairing,
// {
//     pub fn new(g1_points: Vec<E::G1Affine>, g2_points: Vec<E::G2Affine>) -> PairingTuple<E> {
//         assert_eq!(g1_points.len(), g2_points.len(), "Bases lengths must match");

//         let pairing_vec: Vec<(E::G1Affine, E::G2Affine)> = g1_points
//             .iter()
//             .zip(g2_points.iter())
//             .map(|(g1, g2)| (g1.clone(), g2.clone()))
//             .collect();
//         PairingTuple { pairing_vec }
//     }
// }

// pub struct PairingTupleWithWitness<E: Pairing> {
//     pub pairing_vec: Vec<(E::G1Affine, E::G2Affine)>,
// }

// impl<E> PairingTupleWithWitness<E>
// where
//     E: Pairing,
// {
//     pub fn new(
//         g1_points: Vec<E::G1Affine>,
//         g2_points: Vec<E::G2Affine>,
//         witnesses: Vec<E::ScalarField>,
//     ) -> PairingTupleWithWitness<E> {
//         assert_eq!(g1_points.len(), g2_points.len(), "Bases lengths must match");
//         assert_eq!(g1_points.len(), witnesses.len(), "Bases lengths must match");

//         let pairing_vec: Vec<(E::G1Affine, E::G2Affine)> = g1_points
//             .into_iter()
//             .zip(g2_points.into_iter())
//             .zip(witnesses.into_iter())
//             .map(|((g1, g2), witness)| {
//                 let scaled_g1 = (g1.into_group() * witness).into_affine();
//                 (scaled_g1, g2)
//             })
//             .collect();

//         Self { pairing_vec }
//     }
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use ark_bls12_381::{fr::Fr, Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
//     use ark_ec::CurveGroup;
//     use ark_std::{rand::Rng, test_rng, UniformRand};

//     fn gen_pairing_tuple_with_witness<R: Rng + Send>(
//         r: &mut R,
//     ) -> PairingTupleWithWitness<Bls12_381> {
//         let mut rng = test_rng();
//         let g1r_points = (0..3)
//             .map(|_| G1Projective::rand(&mut rng).into_affine())
//             .collect::<Vec<_>>();

//         let g2r_points = (0..3)
//             .map(|_| G2Projective::rand(&mut rng).into_affine())
//             .collect::<Vec<_>>();

//         let witnesses = (0..3).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

//         let tuple = PairingTupleWithWitness::<Bls12_381>::new(
//             g1r_points.clone(),
//             g2r_points.clone(),
//             witnesses.clone(),
//         );
//         tuple
//     }

//     fn gen_pairing_tuple<R: Rng + Send>(r: &mut R) -> PairingTuple<Bls12_381> {
//         let mut rng = test_rng();
//         let g1r_points = (0..3)
//             .map(|_| G1Projective::rand(&mut rng).into_affine())
//             .collect::<Vec<_>>();

//         let g2r_points = (0..3)
//             .map(|_| G2Projective::rand(&mut rng).into_affine())
//             .collect::<Vec<_>>();

//         let tuple = PairingTuple::<Bls12_381>::new(g1r_points.clone(), g2r_points.clone());
//         tuple
//     }

//     #[test]
//     fn test_pairing_tuple_with_witness() {
//         let tuple = gen_pairing_tuple_with_witness(&mut test_rng());
//         assert_eq!(tuple.pairing_vec.len(), 3);
//     }

//     #[test]
//     fn test_pairing_tuple() {
//         let tuple = gen_pairing_tuple(&mut test_rng());
//         assert_eq!(tuple.pairing_vec.len(), 3);
//     }
// }
