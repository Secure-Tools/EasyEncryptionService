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

#[cfg(test)]
mod tests {
    use base_62::decode;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use crate::signature::{create_signature, verify_signature};

    const TEST_PRIV_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\r\n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\r\nYzxZYlaS/Ad9P1tBo1qoPJisbmXdZg==\r\n-----END PRIVATE KEY-----\r\n";

    #[test]
    fn test_signature_creation() {
        let plain_text = "Hello this is a test for signature generation.";

        let priv_key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIV_KEY_PEM).unwrap();

        let signature = create_signature(plain_text, &priv_key)
            .unwrap();

        let correct_signature = "ZMLSmKTjz8EBmVJSY7VFNjVFAJsExYrzQYwyItS5Ftev0WLG0nLwrmSPbprxDpfzPYow9rwjZUmkjCfHVFM0Q4b6Qom2Z6ZSRzceL7aHWyB50W8lXrvy3d8n0CMvpxBtvNUuwIRmQDTYhsdSqz0LnWCrbE02EmTV0lHajYkAgciFpj1PvPC8nQycC3JsX7qbx1Xvvrx2BGwGRdBJWMnkMK3s6CHo8yCrEreyn1KbEIfTYnp8zbafckj2ZnQPjy2zQeV2Sn9cKmx5hR0LekLWDDZEF4dniMMzi1oeQqUZKWcbIlV0BCaEydMekEx5oTpsu1ZLqlbUuXF0QG49HO1YUq3C7lFTnwI8EnQVSE2RMfRPETiIk1cglwiQnvczAVMOsWvzk1h8H2NBZ8QF9AjGjZHIwAKGbEFOyuGeEMw84I2W12o6IIIQMdxwiocE8y7349OXifYCglsI124DTnP0cLi4DgUiNlnNA6Rj6SX5rtkKh1Zj59jSTuKgzfbcmC5nrzvfIlnhGam0RMEvbwYDnD34Eak1xy5IM1Ort5vAp4q9llGs0Pt0lAzyYtVXfeqGQRgmXeLqFaZRQQratfQy5Btv7BYfYJWOowFQ48gSZJgKEgE4IqCFI4QAbYMsOCjxuQbLs4HA79YeUuzMPRAuapvwTCU9xVikvDTBpbM9XMzzRGu71";
        let correct_signature = decode(correct_signature).unwrap();
        assert_eq!(correct_signature, signature);
    }

    #[test]
    fn test_signature_verification() {
        let plain_text = "Hello this is a test for signature generation.";

        let priv_key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIV_KEY_PEM).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let signature = create_signature(plain_text, &priv_key)
            .unwrap();

        let signature_verification = verify_signature(plain_text, signature.as_slice(), &pub_key);
        assert!(signature_verification.is_ok());
    }

    #[test]
    fn test_tampered_message() {
        let priv_key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIV_KEY_PEM).unwrap();
        let pub_key = RsaPublicKey::from(&priv_key);
        let signature = create_signature("original message", &priv_key).unwrap();

        assert!(verify_signature("tampered message", &signature, &pub_key).is_err());
    }
}