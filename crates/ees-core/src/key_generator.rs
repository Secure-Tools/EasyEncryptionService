use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};

pub fn generate_rsa_key() -> anyhow::Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}

/// ## FOR TEST PURPOSES ONLY, DO NOT USE IN PRODUCTION
pub fn generate_rsa_key_test() -> anyhow::Result<(RsaPublicKey, RsaPrivateKey)> {
    let mut rng = rand::rng();
    const RSA_KEY_BITS: usize = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;
    let public_key = RsaPublicKey::from(&private_key);

    Ok((public_key, private_key))
}