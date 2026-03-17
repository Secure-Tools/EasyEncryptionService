use aes_gcm::Aes256Gcm;

pub type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn u8_to_string(data: Vec<u8>) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(data)
}