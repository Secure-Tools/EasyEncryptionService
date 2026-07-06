use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use anyhow::Result;

pub fn fetch_key_from_file(path : &str) -> Result<RsaPrivateKey> {
    Ok(RsaPrivateKey::read_pkcs8_der_file(path)?)
}

pub fn save_key_to_file(path : &str, private_key : &rsa::RsaPrivateKey) -> Result<()> {
    private_key.write_pkcs8_der_file(path)?;
    Ok(())
}