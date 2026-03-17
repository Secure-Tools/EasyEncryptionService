use crate::key_generator::{fetch_key_from_file, generate_rsa_key, save_key_to_file};
use crate::rsa_service::{encrypt_rsa, decrypt_rsa};
use crate::helper::u8_to_string;
use crate::aes_service::{encrypt_aes, decrypt_aes};
use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid};
use crate::packer::{pack_message, pack_public_key, unpack_message, unpack_public_key};
use clap::{Parser, Subcommand};

pub mod key_generator;
pub mod helper;
pub mod rsa_service;
pub mod aes_service;
pub mod hybrid_encryption;
pub mod packer;

#[derive(Parser)]
#[command(name = "ees", about = "Easy encryption service CLI tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate,
    /// Encrypts a text using a base62 encoded RSA public key.
    Encrypt {
        #[arg(short, long)]
        text: String,
        // Base62 encoded RSA public key
        #[arg(short, long)]
        pub_key: String
    },
    /// Decrypts a text using your private key.
    Decrypt {
        #[arg(short, long)]
        text: String,
        /// Path to .pcks8 private key file (default: private_key.pkcs8)
        #[arg(short, long, default_value = "private_key.pkcs8")]
        key_file: String,
    }
}
fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate => {
            let (pub_key, priv_key) = generate_rsa_key();
            save_key_to_file("private_key.pkcs8", &priv_key);
            println!("\nRSA key generation successful! \n \
            Private key has been saved to private_key.pkcs8. \n\
            Public key: {}", pack_public_key(&pub_key));
        }
        Command::Encrypt {text, pub_key} => {
            let pub_key = pub_key.trim();
            let pub_key = unpack_public_key(pub_key);
            let (cipher_text, nonce, enc_key) = encrypt_hybrid(text.as_bytes(), &pub_key);
            let packed_text = pack_message(&cipher_text, nonce, &enc_key);
            println!("\nEncrypted message: {}", packed_text);
        }
        Command::Decrypt {text, key_file} => {
            let key_file = key_file.trim();
            let (cipher_text, nonce, enc_key) = unpack_message(&text);
            let extracted_text = decrypt_hybrid(&cipher_text, nonce, &enc_key , &fetch_key_from_file(&key_file));
            println!("\nDecrypted message: {}", u8_to_string(extracted_text));
        }
    }
}
