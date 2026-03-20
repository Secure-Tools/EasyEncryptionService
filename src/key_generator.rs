use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use anyhow::Result;

pub fn generate_rsa_key() -> Result<(RsaPublicKey, RsaPrivateKey)>{
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}

pub fn fetch_key_from_file(path : &str) -> Result<RsaPrivateKey> {
    Ok(RsaPrivateKey::read_pkcs8_der_file(path)?)
}

pub fn save_key_to_file(path : &str, private_key : &rsa::RsaPrivateKey) -> Result<()> {
    private_key.write_pkcs8_der_file(path)?;
    Ok(())
}

/// ## FOR TEST PURPOSES ONLY, DO NOT USE IN PRODUCTION
pub fn generate_rsa_key_test() -> Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}