use crate::key_generator::generate_rsa_key;
use crate::rsa_service::encrypt_rsa;
use crate::rsa_service::decrypt_rsa;
use crate::helper::u8_to_string;
use crate::aes_service::{encrypt_aes, decrypt_aes};

pub mod key_generator;
pub mod helper;
pub mod rsa_service;
pub mod aes_service;
pub mod hybrid_encryption;

fn main() {
    let (pub_key, priv_key) = generate_rsa_key();
    let message = b"Let's meet at 4PM!";
    let cipher_message = encrypt_rsa(message, &pub_key);
    let decoded_message = decrypt_rsa(&cipher_message, &priv_key);
    let extracted_message = u8_to_string(decoded_message);

    println!("RSA extracted: {extracted_message}");

    let plain_text = b"Let's meet at 5PM!";
    let (cipher_text, nonce, key) = encrypt_aes(plain_text);
    let extracted_text = decrypt_aes(&cipher_text, nonce , &key);

    println!("AES extracted: {}", u8_to_string(extracted_text));
}
