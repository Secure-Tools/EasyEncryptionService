pub mod key_generator;
pub mod helper;
pub mod rsa_service;
pub mod aes_service;
pub mod hybrid_encryption;
pub mod packer;
pub mod signature;
pub mod key_store;

use wasm_bindgen::prelude::*;
use crate::hybrid_encryption::encrypt_hybrid;
use crate::packer::{pack_message, unpack_public_key};

#[wasm_bindgen]
pub fn encrypt_message(text: &str, pub_key_b62: &str) -> Result<String, JsValue> {
    let pub_key = unpack_public_key(pub_key_b62)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let (cipher_text, nonce, enc_key) = encrypt_hybrid(text.as_bytes(), &pub_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(pack_message(&cipher_text, nonce, &enc_key))
}

use crate::hybrid_encryption::decrypt_hybrid;
use crate::packer::unpack_message;
use crate::helper::u8_to_string;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

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