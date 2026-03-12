use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::LineEnding;

pub fn generate_key() -> (RsaPublicKey, RsaPrivateKey){
    let mut rng = rand::rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key.");
    let public_key = RsaPublicKey::from(&private_key);

    (public_key, private_key)
}
