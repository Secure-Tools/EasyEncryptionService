use aes_gcm::{Aes256Gcm, Key};
use rsa::{RsaPrivateKey, RsaPublicKey};
use crate::aes_service::{decrypt_aes, encrypt_aes};
use crate::rsa_service::{decrypt_rsa, encrypt_rsa};
use crate::helper::AesNonce;
use anyhow::Result;

/// Encrypts the given plain text with AES-GCM and RSA to communicate the text through unencrypted channels.
/// The text is first encrypted with AES-GCM, then the AES key is encrypted with recipients public RSA key.
/// ### Returns:
/// Cipher_text, AES Nonce, Encrypted Key
pub fn encrypt_hybrid(plain_text: &[u8], pub_key : &RsaPublicKey) -> Result<(Vec<u8>, AesNonce, Vec<u8>)>{
    let (cipher_text, nonce, key) = encrypt_aes(plain_text)?;
    let encrypted_key = encrypt_rsa(&key, pub_key)?;
    Ok((cipher_text, nonce, encrypted_key))
}

/// Decrypts the given cipher text.
/// The encrypted key is first decrypted with recipients private key, then the cipher text key is decrypted with AES-GCM.
/// ### Returns:
/// Plain Text
pub fn decrypt_hybrid(cipher_text: &[u8], nonce:AesNonce, encrypted_key: &[u8], priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let key_vector = decrypt_rsa(&encrypted_key, priv_key)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_vector);
    decrypt_aes(cipher_text, nonce, key)
}

#[cfg(test)]
mod tests {
    use crate::key_generator::generate_rsa_key_test;
    use super::*;

    #[test]
    fn test_full_hybrid_cycle() {
        let plain_text = b"Hello this is a test for hybrid encryption";
        let (pub_key, priv_key) = generate_rsa_key_test().unwrap();
        let (cipher_text, nonce, key) = encrypt_hybrid(plain_text, &pub_key).unwrap();
        let decrypted_text = decrypt_hybrid(&cipher_text, nonce, &key, &priv_key).unwrap();
        assert_eq!(plain_text, decrypted_text.as_slice());
    }

}