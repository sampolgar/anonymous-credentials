use sha3::{Digest, Sha3_256};
// mod proof;
// Hashes a string

fn keccak_bytes(hash_bin: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(hash_bin);
    let result = hasher.finalize();
    hex::encode(result)
}

// Hashes a pair of strings. Input: array of strings, start index of the pair. Output: hash of the pair
// If pair is last elem in arr, return hash of that elem. Else, concat the two strings and hash the result.

fn hash_pair(array: &[String], start: usize) -> String {
    if array[start] == array[array.len() - 1] {
        return array[start].clone();
    }

    let merged_pair = format!("{}{}", array[start], array[start + 1]);
    let merge_hash = keccak_bytes(&hex::decode(merged_pair).unwrap());
    merge_hash
}

// Recursively hash pairs of strings until a single hash (root) is left. Input: array of strings. Output: root hash of the Merkle tree

fn merkletree(input_hashes: Vec<String>) -> String {
    println!("hashing: {:?}", input_hashes);
    let mut new_hashes: Vec<String> = Vec::new();

    for x in (0..input_hashes.len()).step_by(2) {
        let new_hash = hash_pair(&input_hashes, x);
        new_hashes.push(new_hash);
    }

    if new_hashes.len() > 1 {
        return merkletree(new_hashes);
    }
    new_hashes[0].clone() // return root hash
}

//Create a tree by hashing leaf nodes into pairs, hashing the pairs into pairs until the root.

fn generatetree() -> String {
    let leaf_nodes = vec!["a", "b", "c", "d", "e", "f", "g", "h"];
    let leaf_hashes: Vec<String> = leaf_nodes
        .iter()
        .map(|&leaf_data| keccak_bytes(leaf_data.as_bytes()))
        .collect();
    let merkle_root = merkletree(leaf_hashes);
    merkle_root
}

fn main() {
    let merkle_root = generatetree();
    println!("Merkle root: {}", merkle_root)
}

// TODO
// 1. Add a function to generate a proof for a leaf node
// 2. Add a function to verify a proof for a leaf node

// hashing: [
//     "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
//     "b039179a8a4ce2c252aa6f2f25798251c19b75fc1508d9d511a191e0487d64a7",
//     "263ab762270d3b73d3e2cddf9acc893bb6bd41110347e5d5e4bd1d3c128ea90a",
//     "4ce8765e720c576f6f5a34ca380b3de5f0912e6e3cc5355542c363891e54594b",
//     "42538602949f370aa331d2c07a1ee7ff26caac9cc676288f94b82eb2188b8465",
//     "a0b37b8bfae8e71330bd8e278e4a45ca916d00475dd8b85e9352533454c9fec8",
//     "9f2898da52dedaca29f05bcac0c8e43e4b9f7cb5707c14cc3f35a567232cec7c",
//     "5a082c81a7e4d5833ee20bd67d2f4d736f679da33e4bebd3838217cb27bec1d3"]

// hashing: [
//     "29df505440ebe180c00857e92b0694c56a33762b08944472492b0cbf6ec607e3",
//     "19a84217e939015aaa26d5da6b9ca673eae0df32877593df597cd3e5157982b1",
//     "e1c2fd1466610da5992816a4f7e2796e8e5051ffefe072c6f28a9fb5ed97bc8c",
//     "1bee13465ffe57f7954bd9f9fb812a8e33d928b6524bf94169056ef5b8aefc6f"
//     ]

// hashing: [
//     "5267fec4a5327f9d287233f95213afa39d3aad2fee1fa1384b032b79fb3441e8",
//     "166afcbc6a473190968af2e514250fd4f47dde89f0c5a4da150759d41646b98c"
//     ]

// Merkle root: 463baccb1666a42a1156e67f5961be418728a5bd80a97fda6d5054496d7646dc
