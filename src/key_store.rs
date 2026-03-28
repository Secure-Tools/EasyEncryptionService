use std::fs::File;
use serde::Serialize;

#[derive(Serialize)]
struct PKeyStore {
    key_name: String,
    encoded_key: String
}

pub fn store(name: String, b62_encoded_key: String) {
    let key_store = PKeyStore {key_name:name.trim().to_string(), encoded_key:b62_encoded_key.trim().to_string()};

    let file = File::create("keyring.json").expect("File couldnt be read/created.");

    serde_json::to_writer_pretty(file, &key_store).expect("Keyring failed to write.");
}