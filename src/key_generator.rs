use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::LineEnding;

pub fn generate_key() {
    let mut rng = rand::rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key.");
    let public_key = RsaPublicKey::from(&private_key);

    let data = b"Hello world!";
    let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
    assert_ne!(&data[..], &enc_data[..]);

    let dec_data = private_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
    assert_eq!(&data[..], &dec_data[..]);

    let decrypted_message = String::from_utf8(dec_data).unwrap();
    println!("Decrypted message: {}", decrypted_message);
}

