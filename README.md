# Easy Encryption Service

## Description
Easy Encryption Service is a program that allows users to encryptedly communicate through public unencrypted channels like forums and comments. 
It is designed to be a simple to use program where users can insert their message and the recepients key to get a encrypted block that can be sent through any channels.
The recepient then pastes the block to the program which outputs the original message.
Messages are signed with sender's private key so the recepient can verify the messages authenticity.
The encrypted block is made with base62 (alphabet characters + numbers) thus it is very easy to copy and paste throughout the internet.
The public keys to share will also be mapped to the base62 so it will also be easy to transfer them.

The Easy Encryption Service uses a hybrid between RSA and AES-GCM encryptions. 
RSA gives functionality to communicate without requiring an encrypted channel through public key cryptography.
AES-GCM compansates for the downsides of RSA by encrypting long messages securely.
The hybrid encryption first encrypts the message with AES-GCM and then encrypts the AES-GCM key with recipients RSA public key.

## Installation
### From release
Download the latest binary for your platform from the Releases page. Binaries are available for Linux (x86_64), macOS (x86_64), and Windows (x86_64).

### Building from source
Make sure you have Rust installed (edition 2024).
```bash
git clone https://github.com/Secure-Tools/EasyEncryptionService.git
cd EasyEncryptionService
cargo build --release
```
The compiled binary will be at target/release/ees (or ees.exe on Windows).


## Usage
The program offers the following CLI commands. Run from the directory containing the ees binary.
### Generation of public/private RSA keys:
```bash
./ees generate
```
This saves private_key.pkcs8 in the current directory and updates the keyring_yours.json file with the base62 encoded public key / path to private key.
### Store public RSA key:
```bash
./ees store -n "CONTACT_NAME" -p "CONTACT_PUBLIC_KEY"
```
This stores the name of the contact and their base62 encoded public key to keyring.json. You need to store the contact before encrypting / decrypting messages.
### Delete a contact:
```bash
./ees delete -n "CONTACT_NAME"
```
Deletes a contact and the corresponding encoded public key from your contact list.
### List contacts:
```bash
./ees list
```
Lists all the names in your contacts. You can only use these for encryption and decryption. Use store command to add more.
### Encrypting a text:
```bash
./ees encrypt -t "I want to encrypt this text" -n "RECIPIENT_NAME" -k "private_key.pkcs8"
```
Provide the text after -t, the recipient's name saved in keyring.json after -n, and your private key file after -k. Alternatively,
```bash
./ees encrypt -t "I want to encrypt this text" -n "RECIPIENT_NAME" 
```
which defaults -k to private_key.pkcs8. The message is encrypted and signed, then output as a base62 block.
### Decrypting a text:
```bash
./ees decrypt -t "ENCRYPTED_BLOCK" -n "SENDER_NAME" -k "private_key.pkcs8"
```
Provide the encrypted block after -t, the sender's name saved in keyring.json after -n for signature verification, and your private key file after -k. Alternatively,
```bash
./ees decrypt -t "ENCRYPTED_BLOCK" -n "SENDER_NAME"
```
which defaults -k to private_key.pkcs8. Outputs the decrypted text and confirms signature validity.
## Testing
Run the test suite with:
```bash
cargo test
```
Tests should be run before every commit.
## Security
EES uses the following cryptographic primitives:
- **AES-256-GCM** via the [`aes-gcm`](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm) crate (RustCrypto)
- **RSA-4096 with OAEP + PSS** via the [`rsa`](https://github.com/RustCrypto/RSA) crate (RustCrypto)

The rsa`crate crate has an open timing side-channel advisory ([RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), Marvin Attack).
The advisory affects network decryption while our implementation handles all encryption/decryption on local device only so this vulnerability does not apply to 
this use case.

## Security policy
If you discover a security vulnerability, please report it responsibly by opening a private security advisory on GitHub rather than a public issue. Do not disclose the vulnerability publicly until it has been addressed.

## Contributing
Contributions are welcome! Please fork the repository before making your changes. Make sure to test with ```cargo test```  and add tests for new functionalities before a pull request.

## Roadmap
Planned features to implement:
- Intuitive UI for generating public/private keys and messages. [@str1ng0](https://github.com/str1ng0)
- Passphrase encryption for private key files. [@benilevi05](https://github.com/benilevi05)
- Clipboard integration. [@benilevi05](https://github.com/benilevi05)

## License
The project is licensed under MIT License which is described in the LICENSE file.
 
