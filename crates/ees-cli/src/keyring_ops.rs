use anyhow::anyhow;
use rsa::Pkcs1v15Sign;
use sha2::Sha256;
use rsa::signature::digest::Digest;
use ees_core::aes_service::encrypt_aes;
use ees_core::helper::AesNonce;
use ees_core::packer::unpack_public_key;
use ees_core::rsa_service::encrypt_rsa;

use crate::key_store::get_enc_key;

pub fn encrypt_hybrid_name(plain_text: &[u8], recipient_name:&str) -> anyhow::Result<(Vec<u8>, AesNonce, Vec<u8>)> {
    let (cipher_text, nonce, key) = encrypt_aes(plain_text)?;
    let pub_key = get_enc_key(recipient_name, "keyring.json")
        .ok_or_else(|| anyhow!("No public key found for {}. Use store command to add.", recipient_name))?;
    let encrypted_key = encrypt_rsa(&key, &unpack_public_key(&pub_key)?)?;
    Ok((cipher_text, nonce, encrypted_key))
}

pub fn verify_signature_name(cipher_text: &str, signature: &[u8], name: &str) -> anyhow::Result<()> {
    let digest = Sha256::digest(cipher_text);
    let pub_key = get_enc_key(name, "keyring.json")
        .ok_or_else(|| anyhow!("No public key found for '{}'. Use store command to add.", name))?;
    unpack_public_key(&pub_key)?.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .map_err(|e| anyhow!("Verification failed: {:?}", e))
}