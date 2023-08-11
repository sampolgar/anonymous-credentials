use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tiny_keccak::Hasher;

// generate private key at random from secp256k1
// derive public key from private key with secp256k1
// generate vanity address from public key with keccak256

fn main() {
    generate_keys();
}

fn generate_keys() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut OsRng);
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // println!("{:?} {:?}", secret_key, &public_key);

    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&public_key.serialize_uncompressed()[1..]);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    println!("{:?}", &mut output.to_vec());

    let ethereum_address = &output[12..];
    println!("{:?}", &ethereum_address.to_vec());

    let mut eth_address: String = hex::encode(&ethereum_address);
    eth_address = format!("0x{}", eth_address);
    println!("{:?}", &eth_address);
}
