use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use rsa::RsaPublicKey;
use crate::aes_service::encrypt_aes;
use crate::rsa_service::{decrypt_rsa, encrypt_rsa};

type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn encrypt_hybrid(data: &[u8], pub_key : RsaPublicKey) -> (Vec<u8>, AesNonce, Vec<u8>){
    let (cipher_text, nonce, key) = encrypt_aes(data);
    let encrypted_key = encrypt_rsa(key.as_slice(), &pub_key);

    (cipher_text, nonce, encrypted_key)
}