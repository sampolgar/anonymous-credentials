use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

// SecretKey(#0427d5b28f2ae6b4)
// PublicKey(f6fdfeeb1bdde1f6069f0c4babc24ee122ec96c41856543984cdb0c8a4ebfd71a5bc3093db408e28cad0ceb88617928ea6ccb96586a597d25f60badc2978a99a)
// SecretKey(#1c0165545e423228)
// PublicKey(651ba37239e68181322e0df9d987e659f0df5e10ed0a0052a766915a669b862eba636ff811ace83e3bf15c6a0b21ff63a3f32e70e740de5257eca8f3e285f093)

// generate private key at random
// derive public key from private key
// generate address until finding one that matches the address

fn main() {
    println!("Hello, world!");
    generate_keys();
}

fn generate_keys() {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut OsRng);
    let public_key1 = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key2 = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key3 = PublicKey::from_secret_key(&secp, &secret_key);
    println!(
        "{:?} {:?} {:?} {:?}",
        secret_key, public_key1, public_key2, public_key3
    );
    // let message = Message::from_hashed_data::<sha256::Hash>("Hello World!".as_bytes());

    // let sig = secp.sign_ecdsa(&message, &secret_key);
    // assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
}

SecretKey(#35db29d6465beab6) 
PublicKey(b2d146e9885d217cec25b1d3f3c01ed0b52720966fb2863a88eff884a60d24a685ba7f589abe4da680a47ed4390b38d180fd423666c2bc0c6d7baf9eabfae51a) 
PublicKey(b2d146e9885d217cec25b1d3f3c01ed0b52720966fb2863a88eff884a60d24a685ba7f589abe4da680a47ed4390b38d180fd423666c2bc0c6d7baf9eabfae51a) 
PublicKey(b2d146e9885d217cec25b1d3f3c01ed0b52720966fb2863a88eff884a60d24a685ba7f589abe4da680a47ed4390b38d180fd423666c2bc0c6d7baf9eabfae51a)