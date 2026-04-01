use std::collections::HashMap;
use std::fs;
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;

#[derive(Serialize, Deserialize, Default)]
struct Keyring {
    contacts: HashMap<String, String>
}

pub fn store(name: String, b62_encoded_key: String, path: &str) {
    let mut keyring : Keyring = get_keyring(path);

    keyring.contacts.insert(
        name.trim().to_string(), b62_encoded_key.trim().to_string()
    );

    write_keyring(keyring, path);
}

/// Given a name, returns the corresponding encoded public key in the keyring.
pub fn get_enc_key(name:&str, path:&str) -> Option<String> {
    let keyring: Keyring = get_keyring(path);
    keyring.contacts.get(name.trim()).cloned()
}
/// Prints all the contacts.
pub fn list_contacts(path: &str) {
    let keyring: Keyring = get_keyring(path);
    for name in keyring.contacts.keys() {
        println!("{}", name);
    }
}
/// Given a name, removes the name and corresponding public key from the keyring.
pub fn delete_contact(name: &str, path: &str) {
    let mut keyring: Keyring = get_keyring(path);
    keyring.contacts.remove(name);
    write_keyring(keyring, path);

}
/// Stores a base62 encoded public key - private key location pair. Overwrites the previous.
pub fn store_pub_priv_pair(enc_pub_key : &str, priv_key_path : &str) {
    let mut keyring : Keyring = Keyring::default();
    keyring.contacts.insert(enc_pub_key.trim().to_string(), priv_key_path.trim().to_string());
    write_keyring(keyring, "keyring_yours.json");
}

//Gets a base62 encoded public key - private key location pair.
pub fn get_pub_priv_pair() -> (String, String) {
    let keyring : Keyring = get_keyring("keyring_yours.json");
    let mut key_iter = keyring.contacts.iter();
    let (pub_key, priv_key) = key_iter.next().expect("Public private key pair not found! Use the generate function.");
    (pub_key.to_string(), priv_key.to_string())
}

fn get_keyring(path: &str) -> Keyring {
    if Path::new(path).exists() {
        let contents = fs::read_to_string(path).expect("Failed to read");
        serde_json::from_str(&contents).expect("Failed to create json from string.")
    } else {
        Keyring::default()
    }
}

fn write_keyring(keyring: Keyring, path: &str) {
    let file = fs::File::create(path).expect("File couldnt be read/created.");
    serde_json::to_writer_pretty(file, &keyring).expect("Keyring failed to write.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup(path: &str) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_store_and_retrieve() {
        let path = "keyring1.json";
        cleanup(path);
        store("alice".to_string(), "abc123".to_string(), path);
        let key = get_enc_key("alice", path);
        assert_eq!(key, Some("abc123".to_string()));
        cleanup(path);
    }

    #[test]
    fn test_store_multiple_contacts() {
        let path = "keyring2.json";
        cleanup(path);
        store("alice".to_string(), "abc123".to_string(), path);
        store("bob".to_string(), "xyz789".to_string(), path);
        assert_eq!(get_enc_key("alice", path), Some("abc123".to_string()));
        assert_eq!(get_enc_key("bob", path), Some("xyz789".to_string()));
        cleanup(path);
    }

    #[test]
    fn test_store_overwrites_existing_name() {
        let path = "keyring3.json";
        cleanup(path);
        store("alice".to_string(), "oldkey".to_string(), path);
        store("alice".to_string(), "newkey".to_string(), path);
        assert_eq!(get_enc_key("alice", path), Some("newkey".to_string()));
        cleanup(path);
    }

    #[test]
    fn test_get_nonexistent_contact() {
        let path = "keyring4.json";
        cleanup(path);
        let key = get_enc_key("nobody", path);
        assert_eq!(key, None);
        cleanup(path);
    }

    #[test]
    fn test_delete_contact() {
        let path = "keyring5.json";
        cleanup(path);
        store("alice".to_string(), "abc123".to_string(), path);
        delete_contact("alice", path);
        assert_eq!(get_enc_key("alice", path), None);
        cleanup(path);
    }

    #[test]
    fn test_delete_nonexistent_contact_does_not_panic() {
        let path = "keyring6.json";
        cleanup(path);
        delete_contact("ghost", path); // should not panic
        cleanup(path);
    }

    #[test]
    fn test_store_trims_whitespace() {
        let path = "keyring7.json";
        cleanup(path);
        store("  alice  ".to_string(), "  abc123  ".to_string(), path);
        assert_eq!(get_enc_key("alice", path), Some("abc123".to_string()));
        cleanup(path);
    }

    #[test]
    fn test_keyring_persists_across_reads() {
        let path = "keyring8.json";
        cleanup(path);
        store("alice".to_string(), "abc123".to_string(), path);
        let keyring = get_keyring(path);
        assert_eq!(keyring.contacts.get("alice"), Some(&"abc123".to_string()));
        cleanup(path);
    }
}
