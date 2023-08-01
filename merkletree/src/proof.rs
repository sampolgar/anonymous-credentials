use sha3::{Digest, Sha3_256};

// fn generate_proof(leaf_index: usize, leaf_hashes: &[String]) -> (String, Vec<String>) {
//     let mut proof: Vec<String> = Vec::new();
//     let mut current_index = leaf_index;
//     let mut current_hash = leaf_hashes[leaf_index].clone();

//     for level in 0..leaf_hashes.len().next_power_of_two().trailing_zeros() {
//         let sibling_index = if current_index % 2 == 0 {
//             current_index + 1
//         } else {
//             current_index - 1
//         };

//         let sibling_hash = leaf_hashes[sibling_index].clone();
//         proof.push(sibling_hash.clone());

//         current_index /= 2;

//         current_hash = if current_index % 2 == 0 {
//             hash_pair(&[current_hash, sibling_hash], 0)
//         } else {
//             hash_pair(&[sibling_hash, current_hash], 0)
//         };
//     }
//     (current_hash, proof)
}
