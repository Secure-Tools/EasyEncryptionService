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
The program offers 3 main functionalities. Run from the directory containing the ees binary.
### Generation of public/private RSA keys:
```bash
./ees generate
```
This outputs the public key encoded in base62 to the console and saves private_key.pkcs8 in the current directory.
### Encrypting a text:
```bash
./ees encrypt -t "I want to encrypt this text" -p "RECIPIENT_PUBLIC_KEY" -k "private_key.pkcs8"
```
Provide the text after -t, the recipient's base62 public key after -p, and your private key file after -k. Alternatively,
```bash
./ees encrypt -t "I want to encrypt this text" -p "RECIPIENT_PUBLIC_KEY" 
```
which defaults -k to private_key.pkcs8. The message is encrypted and signed, then output as a base62 block.
### Decrypting a text:
```bash
./ees decrypt -t "ENCRYPTED_BLOCK" -p "SENDER_PUBLIC_KEY" -k "private_key.pkcs8"
```
Provide the encrypted block after -t, the sender's base62 public key after -p for signature verification, and your private key file after -k. Alternatively,
```bash
./ees decrypt -t "ENCRYPTED_BLOCK" -p "SENDER_PUBLIC_KEY"
```
which defaults -k to private_key.pkcs8. Outputs the decrypted text and confirms signature validity.
## Testing
Run the test suite with:
```bash
cargo test
```
Tests should be run before every commit.
## Security policy
If you discover a security vulnerability, please report it responsibly by opening a private security advisory on GitHub rather than a public issue. Do not disclose the vulnerability publicly until it has been addressed.

## Contributing
Contributions are welcome! Please fork the repository before making your changes. Make sure to test with ```cargo test```  and add tests for new functionalities before a pull request.

## Roadmap
Planned features to implement:
- Intuitive UI for generating public/private keys and messages.
- Storing public/private key pairs with encryption and recipient public keys with names for easy message encryptions without future key exchanges.
- A way to public key exchange with someone from the app itself without any hosted server.

## License
The project is licensed under MIT License which is described in the LICENSE file.
 
