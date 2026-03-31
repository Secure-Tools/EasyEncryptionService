use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};
use std::path::Path;
use serde_json;

#[derive(Serialize, Deserialize, Default)]
struct Keyring {
    contacts: HashMap<String, String>
}

pub fn store(name: String, b62_encoded_key: String) {
    let path = "keyring.json";
    let mut keyring : Keyring = get_keyring(path);

    keyring.contacts.insert(
        name.trim().to_string(), b62_encoded_key.trim().to_string()
    );

    write_keyring(keyring);
}

/// Given a name, returns the corresponding encoded public key in the keyring.
pub fn get_enc_key(name:&str) -> Option<String> {
    let keyring: Keyring = get_keyring("keyring.json");
    keyring.contacts.get(name).cloned()
}
/// Prints all the contacts.
pub fn list_contacts() {
    let keyring: Keyring = get_keyring("keyring.json");
    for name in keyring.contacts.keys() {
        println!("{}", name);
    }
}

pub fn delete_contact(name: &str) {
    let mut keyring: Keyring = get_keyring("keyring.json");
    keyring.contacts.remove(name);
    write_keyring(keyring);

}

fn get_keyring(path: &str) -> Keyring {
    if Path::new(path).exists() {
        let contents = fs::read_to_string(path).expect("Failed to read");
        serde_json::from_str(&contents).expect("Failed to create json from string.")
    } else {
        Keyring::default()
    }
}

fn write_keyring(keyring: Keyring) {
    let file = fs::File::create("keyring.json").expect("File couldnt be read/created.");
    serde_json::to_writer_pretty(file, &keyring).expect("Keyring failed to write.");
}