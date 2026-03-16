use aes_gcm::Aes256Gcm;

pub type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn u8_to_string(data: Vec<u8>) -> String {
    String::from_utf8(data).expect("u8 to string error.")
}