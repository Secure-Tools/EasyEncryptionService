use crate::key_io::{fetch_key_from_file, save_key_to_file};
use ees_core::helper::{u8_to_string, check_priv_key_format};
use ees_core::hybrid_encryption::{decrypt_hybrid};
use ees_core::packer::{pack_message, pack_public_key, pack_signed_message, unpack_message, unpack_signed_message};
use ees_core::signature::{create_signature};
use ees_core::key_generator::generate_rsa_key;
use crate::key_store::{delete_contact, list_contacts, store, store_pub_priv_pair};
use crate::keyring_ops::{encrypt_hybrid_name, verify_signature_name};
use clap::{Parser, Subcommand};
use anyhow::anyhow;


pub mod key_io;
pub mod key_store;
pub mod keyring_ops;

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
        // Name of the recipient
        #[arg(short, long)]
        name: String,
        /// Path to .pkcs8 private key file (default: private_key.pkcs8)
        #[arg(short, long, default_value = "private_key.pkcs8")]
        key_file: String
    },
    /// Decrypts a text using your private key signature with.
    Decrypt {
        #[arg(short, long)]
        text: String,
        /// Path to .pkcs8 private key file (default: private_key.pkcs8)
        #[arg(short, long, default_value = "private_key.pkcs8")]
        key_file: String,
        // Senders name. Must be stored in keyring.json by using store command first.
        #[arg(short, long)]
        name: String,
    },
    /// Stores a (name, base62 encoded RSA public key) pair in keyring.json.
    Store {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        pub_key: String,
    },
    Delete {
      #[arg(short, long)]
      name: String,
    },
    List
}
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let default_keyring = "keyring.json";

    match cli.command {
        Command::Generate => {
            let priv_key_path = "private_key.pkcs8";
            let (pub_key, priv_key) = generate_rsa_key()?;
            save_key_to_file(priv_key_path, &priv_key)?;
            store_pub_priv_pair(&pack_public_key(&pub_key)?, priv_key_path);
            println!("\nRSA key generation successful! \n \
            Private key has been saved to private_key.pkcs8. \n\
            Public key saved to keyring_yours.json.");
        }
        Command::Encrypt {text, name, key_file} => {
            let key_file = key_file.trim();
            if  !check_priv_key_format(key_file)?{
                return Err(anyhow!("Invalid file format..."))
            }
            let priv_key = &fetch_key_from_file(&key_file)?;
            let (cipher_text, nonce, enc_key) = encrypt_hybrid_name(text.as_bytes(), name.trim())?;
            let packed_text = pack_message(&cipher_text, nonce, &enc_key);
            let signature = create_signature(&packed_text, &priv_key)
                .map_err(|e| anyhow!("Could not create signature: {}", e))?;
            let packed_signed_text = pack_signed_message(&packed_text, &signature);
            println!("\nEncrypted message: {}", packed_signed_text);
        }
        Command::Decrypt {text, key_file, name} => {
            let key_file = key_file.trim();
            if  !check_priv_key_format(key_file)?{
                return Err(anyhow!("Invalid file format..."))
            }
            let text = text.trim();
            let (text, sig_bytes) = unpack_signed_message(&text)?;
            let (cipher_text, nonce, enc_key) = unpack_message(&text)?;
            verify_signature_name(&text, &sig_bytes, name.trim())
                .map_err(|e| anyhow!("Signature verification failed: {}", e))?;
            let extracted_text = decrypt_hybrid(&cipher_text, nonce, &enc_key , &fetch_key_from_file(&key_file)?)?;
            println!("\nDecrypted message: {}", u8_to_string(extracted_text)?);
            println!("Signature verified");
        }
        Command::Store {name, pub_key} => {
            store(name, pub_key, default_keyring);
            println!("Public key stored!");
        }
        Command::Delete {name} => {
            let res = delete_contact(name.trim(), default_keyring);
            if res == true {
                println!("Contact {} deleted!", name);
            } else {
                println!("{} not in the keyring!", name);
            }
        }

        Command::List => {
            list_contacts(default_keyring);
        }
    }
    Ok(())
}
