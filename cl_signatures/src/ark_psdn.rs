// // https://lib.rs/crates/arkworks-native-gadgets
// use ark_ff::{BigInteger, PrimeField};
// use ark_std::{error::Error as ArkError, io::Read, rand::Rng, string::ToString, vec::Vec};

// use arkworks_native_gadgets::{
//     // merkle_tree::SparseMerkleTree,
//     poseidon::{sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters},
// };

// use arkworks_utils::*;

// pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
// 	let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

// 	let mds_f = bytes_matrix_to_f(&pos_data.mds);
// 	let rounds_f = bytes_vec_to_f(&pos_data.rounds);

// 	PoseidonParameters {
// 		mds_matrix: mds_f,
// 		round_keys: rounds_f,
// 		full_rounds: pos_data.full_rounds,
// 		partial_rounds: pos_data.partial_rounds,
// 		sbox: PoseidonSbox(pos_data.exp),
// 		width: pos_data.width,
// 	}
// }
