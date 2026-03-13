use crate::key_generator::generate_key;
use crate::rsa_service::encrypt_message_rsa;
use crate::rsa_service::decrypt_message_rsa;
use crate::helper::u8_to_string;

pub mod key_generator;
pub mod helper;
pub mod rsa_service;

fn main() {
    let (pub_key, priv_key) = generate_key();
    let message = b"Let's meet at 4PM!";
    let cipher_message = encrypt_message_rsa(message, pub_key);
    let decoded_message = decrypt_message_rsa(&cipher_message, priv_key);
    let extracted_message = u8_to_string(decoded_message);

    println!("Extracted message: {extracted_message}");

}