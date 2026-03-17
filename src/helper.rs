use aes_gcm::Aes256Gcm;
use anyhow::{Result, anyhow};

pub type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn u8_to_string(data: Vec<u8>) -> Result<String> {
    String::from_utf8(data).map_err(|_| anyhow!("Decrypted message is not valid UTF-8"))

}