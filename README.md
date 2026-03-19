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

## Dependencies (TODO)

## Installation (TODO)

## Usage
This section is to use the program with CLI tools. First go to the directory with the executable binary. By default,
```bash
cd EasyEncryptionService/target/build
```
The program offers 3 main functionalities:
### Generation of public/private RSA keys:
```bash
./ees generate
```
This will output the public text encoded in base62 on the console and save private_key.pkcs8 as a file in the same directory.
### Encrypting a text:
```bash
./ees encrypt -t "I want to encrypt this text" -p "PUBLIC KEY"
```
You need to input the text you want to encrypt after -t and the recipients public key after -p.
This will output the encrypted block to be sent.
### Decrypting a text:
```bash
./ees decrypt -t "ENCRYPTED BLOCK" -k "private_key.pkcs8"
```
Inputting the encrypted text after -t and private key file location after -k (it is private_key.pkcs8 by default) will give the decrypted text.
## Testing (TODO)

## Security policy (TODO)

## Contributing (TODO)

## Roadmap
As of 14/03/2026 the following features are planned.
- Base62 encoder/decoder for easy ciphertext sharing. :white_check_mark:
- Signitures for checking messages authenticity. [@str1ng0](https://github.com/str1ng0)
- CLI commands for creating keys and encrypted messages. [@benilevi05](https://github.com/benilevi05) :white_check_mark:

The above features are for the software to function as basic as possible. For the future, the following would be great to implement.
- Intuitive UI for generating public/private keys and messages.
- Storing public/private key pairs with encryption and recipient public keys with names for easy message encryptions without future key exchanges. @str1ng0
- A way to public key exchange with someone from the app itself without any hosted server.

## License
The project is licensed under MIT License which is described in the LICENSE file.
 
