fn main() {
//generate vanity address from public key with keccak256
let eth_prefix: &str = "0x00";
let (secret_key, public_key) = generate_key_pair();

    while true {
        let eth_address = generate_eth_address(public_key);
        if eth_address.starts_with(eth_prefix) {
            println!("Found vanity address: {}", eth_address);
            break;
        }
    }

}

fn generate_key_pair() -> (SecretKey, PublicKey) {
let secp = Secp256k1::new();
let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
return (secret_key, public_key);
}

fn generate_eth_address(public_key: PublicKey) -> String {
let mut hasher = tiny_keccak::Keccak::v256();
hasher.update(&public_key.serialize_uncompressed()[1..]);
let mut output = [0u8; 32];
hasher.finalize(&mut output);
let ethereum_address = &output[12..];
let mut eth_address: String = hex::encode(&ethereum_address);
eth_address = format!("0x{}", eth_address);
println!("{:?}", &eth_address);
return eth_address;
}
