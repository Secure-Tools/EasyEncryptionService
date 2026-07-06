use wasm_bindgen::prelude::*;
use ees_core::hybrid_encryption::{encrypt_hybrid, decrypt_hybrid};
use ees_core::packer::{pack_message, unpack_message, unpack_public_key};
use ees_core::helper::u8_to_string;
use rsa::pkcs8::DecodePrivateKey;
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
pub fn decrypt_message(packed: &str, priv_key_der: &[u8]) -> Result<String, JsValue> {
    let priv_key = RsaPrivateKey::from_pkcs8_der(priv_key_der)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (cipher_text, nonce, enc_key) = unpack_message(packed)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let plain_bytes = decrypt_hybrid(&cipher_text, nonce, &enc_key, &priv_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    u8_to_string(plain_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}