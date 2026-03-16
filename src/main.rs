use crate::key_generator::generate_rsa_key;
use crate::rsa_service::{encrypt_rsa, decrypt_rsa};
use crate::helper::u8_to_string;
use crate::aes_service::{encrypt_aes, decrypt_aes};
use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid};
use crate::packer::{pack_message, unpack_message};

pub mod key_generator;
pub mod helper;
pub mod rsa_service;
pub mod aes_service;
pub mod hybrid_encryption;
pub mod packer;

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

    let plain_text = b"Let's meet at 6PM!";
    let (cipher_text, nonce, enc_key) = encrypt_hybrid(plain_text, &pub_key);
    let extracted_text = decrypt_hybrid(&cipher_text, nonce, &enc_key, &priv_key);

    println!("Hybrid extracted: {}", u8_to_string(extracted_text));

    let plain_text = b"Let's meet at 7PM!";
    let (cipher_text, nonce, enc_key) = encrypt_hybrid(plain_text, &pub_key);
    let packed_data = pack_message(&cipher_text, nonce, &enc_key);
    println!("Packed data: {}", packed_data);
    let (cipher_text, nonce, enc_key) = unpack_message(&packed_data);
    let extracted_text = decrypt_hybrid(&cipher_text, nonce, &enc_key, &priv_key);

    println!("Packed extracted: {}", u8_to_string(extracted_text));
}
