use base_62::{encode, decode};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey};
use rsa::RsaPublicKey;
use crate::helper::AesNonce;

pub fn pack_message(ciphertext: &[u8], nonce: AesNonce, enc_key: &[u8]) -> String {
    let cipher_code = encode(ciphertext);
    let nonce_code = encode(&nonce);
    let enc_key_code = encode(enc_key);

    let packed_cipher = format!("{cipher_code}|{nonce_code}|{enc_key_code}");
    packed_cipher
}

pub fn unpack_message(packed_cipher: &str) -> (Vec<u8>, AesNonce,  Vec<u8>) {
    let mut split = packed_cipher.split('|');
    let ciphertext = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce = decode(split.next().unwrap()).expect("Failed to decode.");
    let enc_key = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce: AesNonce = AesNonce::clone_from_slice(&nonce);
    (ciphertext, nonce, enc_key)
}

pub fn pack_public_key(pub_key:&RsaPublicKey) -> String {
    encode(pub_key.to_public_key_der().expect("Failed to der").as_bytes())
}

pub fn unpack_public_key(pub_key_packed :String) -> RsaPublicKey {
    let der_bytes = decode(&pub_key_packed).expect("Failed to decode");
    RsaPublicKey::from_public_key_der(&der_bytes).expect("Failed to generate public key from bytes")
}