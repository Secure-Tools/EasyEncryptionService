use base_62::{encode, decode};
use rsa::pkcs8::{EncodePublicKey, DecodePublicKey};
use rsa::RsaPublicKey;
use crate::helper::AesNonce;
use anyhow::{Result, Context};

pub fn pack_message(ciphertext: &[u8], nonce: AesNonce, enc_key: &[u8]) -> String {
    let cipher_code = encode(ciphertext);
    let nonce_code = encode(&nonce);
    let enc_key_code = encode(enc_key);

    let packed_cipher = format!("{cipher_code}.{nonce_code}.{enc_key_code}");
    packed_cipher
}

pub fn unpack_message(packed_cipher: &str) -> Result<(Vec<u8>, AesNonce,  Vec<u8>)> {
    let packed_cipher = packed_cipher.trim();
    let mut split = packed_cipher.split('.');
    let ciphertext = decode(split.next().context("Missing ciphertext segment")?)
        .map_err(|e| anyhow::anyhow!("Failed to decode ciphertext: {:?}", e))?;
    let nonce = decode(split.next().context("Missing nonce segment")?)
        .map_err(|e | anyhow::anyhow!("Failed to decode nonce: {:?}", e))?;
    let enc_key = decode(split.next().context("Missing key segment")?)
        .map_err(|e| anyhow::anyhow!("Failed to decode public key: {:?}", e))?;

    let nonce: AesNonce = AesNonce::clone_from_slice(&nonce);
    Ok((ciphertext, nonce, enc_key))
}

pub fn pack_public_key(pub_key:&RsaPublicKey) -> Result<String> {
    Ok(encode(pub_key.to_public_key_der()?.as_bytes()))
}

pub fn unpack_public_key(pub_key_packed :&str) -> Result<RsaPublicKey> {
    let pub_key_packed = pub_key_packed.trim();
    let der_bytes = decode(&pub_key_packed)
        .map_err(|e| anyhow::anyhow!("Failed to unpack public key: {:?}", e))?;
    Ok(RsaPublicKey::from_public_key_der(&der_bytes)?)
}

pub fn pack_signed_message(packed_message: &str, signature: &[u8]) -> String{
    let signature_encoded = encode(signature);
     format!("{packed_message}-{signature_encoded}")
}

pub fn unpack_signed_message(signed_message : &str) -> Result<(&str, Vec<u8>)>{
    let mut split = signed_message.splitn(2, '-');
    let packed_message = split.next().context("Missing cipher segment.")?;
    let signature = decode(split.next().context("Missing signature segment.")?.trim())
        .map_err(|e| anyhow::anyhow!("Failed to unpack the signature: {:?}", e))?;
    Ok((packed_message, signature))
}

#[cfg(test)]
mod tests {
    use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid};
    use crate::key_generator::generate_rsa_key_test;
    use super::*;

    #[test]
    fn test_full_pack_cycle() {
        let plain_text = b"Hello this is a test for hybrid encryption";
        let (pub_key, priv_key) = generate_rsa_key_test().unwrap();
        let (cipher_text, nonce, enc_key) = encrypt_hybrid(plain_text, &pub_key).unwrap();
        let packed_data = pack_message(&cipher_text, nonce, &enc_key);
        let (cipher_text, nonce, key) = unpack_message(&packed_data).unwrap();
        let decrypted_text = decrypt_hybrid(&cipher_text, nonce, &key, &priv_key).unwrap();
        assert_eq!(plain_text, decrypted_text.as_slice());
    }

    #[test]
    fn test_pack_for_public_key() {
        let (pub_key, _priv_key) = generate_rsa_key_test().unwrap();
        let encoded_key = pack_public_key(&pub_key).unwrap();
        let decoded_key = unpack_public_key(&encoded_key).unwrap();
        assert_eq!(pub_key,decoded_key);
    }

}