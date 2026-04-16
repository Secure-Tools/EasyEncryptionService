use std::path::Path;
use aes_gcm::Aes256Gcm;
use rpassword;
use arboard;
use std::{thread, time::Duration};
use anyhow::{Result, anyhow};

pub type AesNonce = aes_gcm::aead::Nonce<Aes256Gcm>;

pub fn u8_to_string(data: Vec<u8>) -> Result<String> {
    String::from_utf8(data).map_err(|_| anyhow!("Decrypted message is not valid UTF-8"))

}

pub fn check_priv_key_format(priv_key :&str) -> Result<bool> {
    match Path::new(priv_key).extension() {
        Some(ext) => Ok(ext == "pkcs8"),
        None => Ok(false),
    }
}

pub fn ask_for_passphrase() -> Result<String> {
    Ok(rpassword::prompt_password("Your password: ")?)
}

pub fn copy_message_to_clipboard(message : &str) -> Result<()> {
    let mut clipboard = arboard::Clipboard::new()?;
    // Fixes Linux clipboard behaviour by waiting before dropping the clipboard.
    // This blocks the main thread which is fine for our CLI program but may need to be changed for the future.
    clipboard.set_text(message)?;
    thread::sleep(Duration::from_millis(500));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priv_key_format_ok() {
        let priv_file = "asd.pkcs8";
        assert!(check_priv_key_format(priv_file).unwrap());
    }
    #[test]
    fn test_priv_key_format_err() {
        let priv_file = "asd.wrong";
        assert!(!check_priv_key_format(priv_file).unwrap());
    }
}