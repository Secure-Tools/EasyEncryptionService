use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::LineEnding;

pub fn generate_key() -> (RsaPublicKey, RsaPrivateKey){
    let mut rng = rand::rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key.");
    let public_key = RsaPublicKey::from(&private_key);

    (public_key, private_key)
}
fn fetch_key_from_file(path : &str) -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::read_pkcs8_der_file(path).expect("Could not read private key")
}

fn save_key_to_file(path : &str, private_key : &rsa::RsaPrivateKey) {
    private_key.write_pkcs8_der_file(path).expect("Could not write private key as PEM")
}