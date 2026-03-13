use aes_gcm::{Aes256Gcm, Nonce, Key, aead::{Aead, AeadCore, KeyInit, OsRng}, AesGcm};
type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

use crate::helper::u8_to_string;

pub fn generate_aes_key() -> Key<Aes256Gcm> {
    Aes256Gcm::generate_key(OsRng)
}

pub fn encrypt_aes(plaintext: &[u8], &key: &Key<Aes256Gcm>) -> (Vec<u8>, AesNonce) {
    let cipher : Aes256Gcm = Aes256Gcm::new(&key);
    let nonce : AesNonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption error.");
    (ciphertext, nonce)
}

pub fn decrypt_aes(ciphertext : &[u8], nonce : AesNonce, &key : &Key<Aes256Gcm>) -> Vec<u8> {
    let cipher : Aes256Gcm = Aes256Gcm::new(&key);
    cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Decryption error.")
}