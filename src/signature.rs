use anyhow::{anyhow, Result};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::signature::digest::Digest;
use sha2::Sha256;

pub fn create_signature(cipher_text: &str, priv_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let digest = Sha256::digest(cipher_text);
    priv_key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| anyhow!("Signing failed: {:?}", e))
}

pub fn verify_signature(cipher_text: &str, signature: &[u8], pub_key: &RsaPublicKey) -> Result<()> {
    let digest = Sha256::digest(cipher_text);
    pub_key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .map_err(|e| anyhow!("Verification failed: {:?}", e))
}