use hex;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tiny_keccak::Hasher;

fn main() {
    let eth_prefix: &str = "0x0000";
    let mut _counter: u32 = 0;

    //iterate until we find a vanity address
    while true {
        let (secret_key, public_key) = generate_key_pair();
        let eth_address = generate_eth_address(public_key);
        _counter += 1;
        if eth_address.starts_with(eth_prefix) {
            println!(
                "Found vanity address: {} after {} counts",
                eth_address, _counter
            );
            break;
        }
    }
}

//generate key pair with secp256k1
fn generate_key_pair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    return (secret_key, public_key);
}

//generate eth address from public key with keccak256 hash. Change format from u8 to hex string
fn generate_eth_address(public_key: PublicKey) -> String {
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&public_key.serialize_uncompressed()[1..]);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    let eth_address_u8 = &output[12..];
    let mut eth_address_str: String = hex::encode(&eth_address_u8);
    eth_address_str = format!("0x{}", eth_address_str);
    println!("{:?}", &eth_address_str);
    return eth_address_str;
}
