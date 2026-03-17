use base_62::{encode, decode};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey};
use rsa::RsaPublicKey;
use crate::helper::AesNonce;

pub fn pack_message(ciphertext: &[u8], nonce: AesNonce, enc_key: &[u8]) -> String {
    let cipher_code = encode(ciphertext);
    let nonce_code = encode(&nonce);
    let enc_key_code = encode(enc_key);

    let packed_cipher = format!("{cipher_code}.{nonce_code}.{enc_key_code}");
    packed_cipher
}

pub fn unpack_message(packed_cipher: &str) -> (Vec<u8>, AesNonce,  Vec<u8>) {
    let packed_cipher = packed_cipher.trim();
    let mut split = packed_cipher.split('.');
    let ciphertext = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce = decode(split.next().unwrap()).expect("Failed to decode.");
    let enc_key = decode(split.next().unwrap()).expect("Failed to decode.");
    let nonce: AesNonce = AesNonce::clone_from_slice(&nonce);
    (ciphertext, nonce, enc_key)
}

pub fn pack_public_key(pub_key:&RsaPublicKey) -> String {
    encode(pub_key.to_public_key_der().expect("Failed to der").as_bytes())
}

pub fn unpack_public_key(pub_key_packed :&str) -> RsaPublicKey {
    let pub_key_packed = pub_key_packed.trim();
    let der_bytes = decode(&pub_key_packed).expect("Failed to decode");
    RsaPublicKey::from_public_key_der(&der_bytes).expect("Failed to generate public key from bytes")
}

#[cfg(test)]
mod tests {
    use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid};
    use crate::key_generator::generate_rsa_key;
    use super::*;

    #[test]
    fn test_full_pack_cycle() {
        let plain_text = b"Hello this is a test for hybrid encryption";
        let (pub_key, priv_key) = generate_rsa_key();
        let (cipher_text, nonce, enc_key) = encrypt_hybrid(plain_text, &pub_key);
        let packed_data = pack_message(&cipher_text, nonce, &enc_key);
        let (cipher_text, nonce, key) = unpack_message(&packed_data);
        let decrypted_text = decrypt_hybrid(&cipher_text, nonce, &key, &priv_key);
        assert_eq!(plain_text, decrypted_text.as_slice());
    }

    #[test]
    fn test_pack_for_public_key() {
        let (pub_key, _priv_key) = generate_rsa_key();
        let encoded_key = pack_public_key(&pub_key);
        let decoded_key = unpack_public_key(&encoded_key);
        assert_eq!(pub_key,decoded_key);
    }

}