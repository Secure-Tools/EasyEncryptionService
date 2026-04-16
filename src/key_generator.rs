use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rsa::pkcs8::der::zeroize::Zeroizing;
use anyhow::Result;
use std::fs;

pub fn generate_rsa_key() -> Result<(RsaPublicKey, RsaPrivateKey)>{
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}

pub fn fetch_key_from_file(path : &str, passphrase : &str) -> Result<RsaPrivateKey> {
    let passphrase = Zeroizing::new(passphrase.as_bytes().to_vec());
    let bytes = fs::read(path)?;
    Ok(RsaPrivateKey::from_pkcs8_encrypted_der(&bytes, &passphrase)?)
}

pub fn save_key_to_file(path : &str, private_key : &rsa::RsaPrivateKey, passphrase : &str) -> Result<()> {
    let mut rng = rand::rng();
    let passphrase = Zeroizing::new(passphrase.as_bytes().to_vec());
    let secret = private_key.to_pkcs8_encrypted_der(&mut rng, &passphrase)?;
    Ok(fs::write(path, secret.as_bytes())?)
}

/// ## FOR TEST PURPOSES ONLY, DO NOT USE IN PRODUCTION
pub fn generate_rsa_key_test() -> Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}