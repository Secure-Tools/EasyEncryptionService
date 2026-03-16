use aes_gcm::Aes256Gcm;
use base_62::{encode, decode};

type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn pack(ciphertext: Vec<u8>, nonce: AesNonce, enc_key: Vec<u8>) -> String {
    let cipher_code = encode(&ciphertext);
    let nonce_code = encode(&nonce.to_vec());
    let enc_key_code = encode(&enc_key);

    let mut packed_cipher = String::new();
    packed_cipher.push_str(&cipher_code);
    packed_cipher.push_str("|");
    packed_cipher.push_str(&nonce_code);
    packed_cipher.push_str("|");
    packed_cipher.push_str(&enc_key_code);
    packed_cipher
}

pub fn unpack(packed_cipher: String) -> (Vec<u8>, AesNonce,  Vec<u8>) {
    let mut split = packed_cipher.split('|');
    let ciphertext = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce = decode(split.next().unwrap()).expect("Failed to decode.");
    let enc_key = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce: AesNonce = AesNonce::clone_from_slice(&nonce);
    (ciphertext, nonce, enc_key)
}