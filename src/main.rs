use crate::key_generator::{fetch_key_from_file, generate_rsa_key, save_key_to_file};
use crate::helper::{u8_to_string, check_priv_key_format};
use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid};
use crate::packer::{pack_message, pack_public_key, pack_signed_message, unpack_message, unpack_public_key, unpack_signed_message};
use crate::key_store::{list_contacts, store};
use clap::{Parser, Subcommand};
use anyhow::anyhow;
use crate::signature::{create_signature, verify_signature};

pub mod key_generator;
pub mod helper;
pub mod rsa_service;
pub mod aes_service;
pub mod hybrid_encryption;
pub mod packer;
pub mod signature;
pub mod key_store;

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
        #[arg(short='p', long)]
        pub_key: String,
        /// Path to .pkcs8 private key file (default: private_key.pkcs8)
        #[arg(short, long, default_value = "private_key.pkcs8")]
        key_file: String
    },
    /// Decrypts a text using your private key.
    Decrypt {
        #[arg(short, long)]
        text: String,
        /// Path to .pkcs8 private key file (default: private_key.pkcs8)
        #[arg(short, long, default_value = "private_key.pkcs8")]
        key_file: String,
        // Base62 encoded RSA public key
        #[arg(short, long)]
        pub_key: String,
    },
    /// Stores a public key
    Store {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        pub_key: String,
    },
    List
}
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate => {
            let (pub_key, priv_key) = generate_rsa_key()?;
            save_key_to_file("private_key.pkcs8", &priv_key)?;
            println!("\nRSA key generation successful! \n \
            Private key has been saved to private_key.pkcs8. \n\
            Public key: {}", pack_public_key(&pub_key)?);
        }
        Command::Encrypt {text, pub_key, key_file} => {
            let key_file = key_file.trim();
            if  !check_priv_key_format(key_file)?{
                return Err(anyhow!("Invalid file format..."))
            }
            let pub_key = pub_key.trim();
            let pub_key = unpack_public_key(pub_key)?;
            let priv_key = &fetch_key_from_file(&key_file)?;
            let (cipher_text, nonce, enc_key) = encrypt_hybrid(text.as_bytes(), &pub_key)?;
            let packed_text = pack_message(&cipher_text, nonce, &enc_key);
            let signature = create_signature(&packed_text, &priv_key)
                .map_err(|e| anyhow!("Could not create signature: {}", e))?;
            let packed_signed_text = pack_signed_message(&packed_text, &signature);
            println!("\nEncrypted message: {}", packed_signed_text);
        }
        Command::Decrypt {text, key_file, pub_key} => {
            let key_file = key_file.trim();
            if  !check_priv_key_format(key_file)?{
                return Err(anyhow!("Invalid file format..."))
            }
            let text = text.trim();
            let (text, sig_bytes) = unpack_signed_message(&text)?;
            let (cipher_text, nonce, enc_key) = unpack_message(&text)?;
            let pub_key = unpack_public_key(pub_key.as_str())?;
            verify_signature(&text, &sig_bytes, &pub_key)
                .map_err(|e| anyhow!("Signature verification failed: {}", e))?;
            let extracted_text = decrypt_hybrid(&cipher_text, nonce, &enc_key , &fetch_key_from_file(&key_file)?)?;
            println!("\nDecrypted message: {}", u8_to_string(extracted_text)?);
            println!("Signature verified");
        }
        Command::Store {name, pub_key} => {
            store(name, pub_key);
            println!("Public key stored!");
        }
        Command::List => {
            list_contacts();
        }
    }
    Ok(())
}
