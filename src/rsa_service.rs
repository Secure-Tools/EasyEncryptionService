use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub fn encrypt_rsa(data: &[u8], pub_key: RsaPublicKey) -> Vec<u8> {
    let mut rng = rand::rng();

    pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt")
}

pub fn decrypt_rsa(cipher_data: &[u8], priv_key: RsaPrivateKey) -> Vec<u8> {
    priv_key.decrypt(Pkcs1v15Encrypt, &cipher_data).expect("failed to decrypt")
}