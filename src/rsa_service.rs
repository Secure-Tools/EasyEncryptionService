use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;


pub fn encrypt_rsa(data: &[u8], pub_key: &RsaPublicKey) -> Vec<u8> {
    let mut rng = rand::rng();

    pub_key.encrypt(&mut rng, Oaep::<Sha256>::new(), &data[..]).expect("failed to encrypt")
}

pub fn decrypt_rsa(cipher_data: &[u8], priv_key: &RsaPrivateKey) -> Vec<u8> {
    priv_key.decrypt(Oaep::<Sha256>::new(), &cipher_data).expect("failed to decrypt")
}