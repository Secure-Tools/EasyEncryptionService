use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use anyhow::{anyhow, Result};

pub fn encrypt_rsa(data: &[u8], pub_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = rand::rng();

    Ok(pub_key.encrypt(&mut rng, Oaep::<Sha256>::new(), &data[..])
        .map_err(|e| anyhow!("RSA encryption failed: {:?}", e))?)
}

pub fn decrypt_rsa(cipher_data: &[u8], priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    Ok(priv_key.decrypt(Oaep::<Sha256>::new(), cipher_data)
        .map_err(|e| anyhow!("RSA decryption failed: {:?}", e))?)
}