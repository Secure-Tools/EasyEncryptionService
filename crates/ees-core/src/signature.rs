use anyhow::{anyhow, Result};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::signature::digest::Digest;
use sha2::Sha256;
use crate::packer::unpack_public_key;

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

#[cfg(test)]
mod tests {
    use crate::key_generator::generate_rsa_key_test;
    use crate::signature::{create_signature, verify_signature};

    #[test]
    fn test_signature_creation_and_verification() {
        let plain_text = "Hello this is a test for signature generation.";

        let (pub_key, priv_key) = generate_rsa_key_test().unwrap();

        let signature = create_signature(plain_text, &priv_key)
            .unwrap();

        assert!(verify_signature(plain_text, &signature, &pub_key).is_ok())
    }

    #[test]
    fn test_tampered_message() {
        let (pub_key, priv_key) = generate_rsa_key_test().unwrap();
        let signature = create_signature("original message", &priv_key).unwrap();

        assert!(verify_signature("tampered message", &signature, &pub_key).is_err());
    }
}