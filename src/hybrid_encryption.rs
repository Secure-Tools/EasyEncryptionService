use aes_gcm::Aes256Gcm;
use aes_gcm::Key;
use rsa::{RsaPrivateKey, RsaPublicKey};
use crate::aes_service::{decrypt_aes, encrypt_aes};
use crate::rsa_service::{decrypt_rsa, encrypt_rsa};

type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn encrypt_hybrid(data: &[u8], pub_key : RsaPublicKey) -> (Vec<u8>, AesNonce, Vec<u8>){
    let (cipher_text, nonce, key) = encrypt_aes(data);
    let encrypted_key = encrypt_rsa(&key, &pub_key);
    (cipher_text, nonce, encrypted_key)
}

pub fn decrypt_hybrid(cipher_text: &[u8], nonce:AesNonce, encrypted_key:Vec<u8>, priv_key:RsaPrivateKey) -> Vec<u8> {
    let key_vector = decrypt_rsa(&encrypted_key, &priv_key);
    let key = Key::<Aes256Gcm>::from_slice(&key_vector);
    decrypt_aes(cipher_text, nonce, key)
}