use aes_gcm::Aes256Gcm;
use anyhow::{Result, anyhow};

pub type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn u8_to_string(data: Vec<u8>) -> Result<String> {
    String::from_utf8(data).map_err(|_| anyhow!("Decrypted message is not valid UTF-8"))

}

pub fn check_priv_key_format(priv_key :&str) -> Result<bool> {
    let split = priv_key.split('.');
    if split.count() != 2 {
        return Ok(false)
    }
    let mut split = priv_key.split('.');
    let name = split.next();
    let extention = split.next().unwrap();
    if extention != "pkcs8" {
        return Ok(false)
    }
    Ok(true)
}