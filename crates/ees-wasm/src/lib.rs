use wasm_bindgen::prelude::*;
use ees_core::hybrid_encryption::{encrypt_hybrid, decrypt_hybrid};
use ees_core::packer::{pack_message, unpack_message, unpack_public_key, pack_public_key};
use ees_core::helper::u8_to_string;
use ees_core::key_generator::generate_rsa_key;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs8::der::zeroize::Zeroizing;
use rsa::RsaPrivateKey;


#[wasm_bindgen]
pub fn encrypt_message(text: &str, pub_key_b62: &str) -> Result<String, JsValue> {
    let pub_key = unpack_public_key(pub_key_b62)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (cipher_text, nonce, enc_key) = encrypt_hybrid(text.as_bytes(), &pub_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(pack_message(&cipher_text, nonce, &enc_key))
}

#[wasm_bindgen]
pub fn decrypt_message(packed: &str, encrypted_priv_der: &[u8], passphrase: &str) -> Result<String, JsValue> {
    let priv_key = RsaPrivateKey::from_pkcs8_encrypted_der(encrypted_priv_der, &passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (cipher_text, nonce, enc_key) = unpack_message(packed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let plain_bytes = decrypt_hybrid(&cipher_text, nonce, &enc_key, &priv_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    u8_to_string(plain_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub struct GeneratedKeypair {
    public_b62: String,
    encrypted_private_der: Vec<u8>,
}

#[wasm_bindgen]
impl GeneratedKeypair {
    #[wasm_bindgen(getter)]
    pub fn public_b62(&self) -> String { self.public_b62.clone() }

    #[wasm_bindgen(getter)]
    pub fn encrypted_private_der(&self) -> Vec<u8> { self.encrypted_private_der.clone() }
}

#[wasm_bindgen]
pub fn generate_and_encrypt_keypair(passphrase: &str) -> Result<GeneratedKeypair, JsValue> {
    let (pub_key, priv_key) = generate_rsa_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let public_b62 = pack_public_key(&pub_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let passphrase = Zeroizing::new(passphrase.as_bytes().to_vec());
    let secret = priv_key
        .to_pkcs8_encrypted_der(&passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(GeneratedKeypair {
        public_b62,
        encrypted_private_der: secret.as_bytes().to_vec(),
    })
}
