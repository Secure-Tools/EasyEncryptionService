use aes_gcm::{Aes256Gcm, Nonce, Key, aead::{Aead, AeadCore, KeyInit, OsRng}};
use crate::helper::u8_to_string;

pub fn generate_aes_key() {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, b"plaintext message".as_ref())
        .expect("Encryption error.");
    let plaintext = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Decryption error.");

    println!("{}", String::from_utf8(plaintext).unwrap());
}