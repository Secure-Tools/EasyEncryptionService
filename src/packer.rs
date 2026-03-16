use aes_gcm::Aes256Gcm;
use base_62::{encode, decode};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey};
use rsa::RsaPublicKey;

type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn pack_message(ciphertext: Vec<u8>, nonce: AesNonce, enc_key: Vec<u8>) -> String {
    let cipher_code = encode(&ciphertext);
    let nonce_code = encode(&nonce.to_vec());
    let enc_key_code = encode(&enc_key);

    let mut packed_cipher = String::new();
    packed_cipher.push_str(&cipher_code);
    packed_cipher.push_str("|");
    packed_cipher.push_str(&nonce_code);
    packed_cipher.push_str("|");
    packed_cipher.push_str(&enc_key_code);
    packed_cipher
}

pub fn unpack_message(packed_cipher: String) -> (Vec<u8>, AesNonce,  Vec<u8>) {
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