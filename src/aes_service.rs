use aes_gcm::{Aes256Gcm, Key, aead::{Aead, AeadCore, KeyInit, OsRng}};
use crate::helper::AesNonce;

pub fn encrypt_aes(plaintext: &[u8]) -> (Vec<u8>, AesNonce, Key<Aes256Gcm>) {
    let key : Key<Aes256Gcm> = Aes256Gcm::generate_key(OsRng);
    let cipher : Aes256Gcm = Aes256Gcm::new(&key);
    let nonce : AesNonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption error.");
    (ciphertext, nonce, key)
}

pub fn decrypt_aes(ciphertext : &[u8], nonce : AesNonce, key : &Key<Aes256Gcm>) -> Vec<u8> {
    let cipher : Aes256Gcm = Aes256Gcm::new(key);
    cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Decryption error.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_aes_cycle() {
        let plain_text = b"Hello this is a test for AES";
        let (cipher_text, nonce, key) = encrypt_aes(plain_text);
        let decrypted_text = decrypt_aes(&cipher_text, nonce, &key);
        assert_eq!(plain_text, decrypted_text.as_slice());
    }

}