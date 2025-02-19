# Encryption
![version](https://img.shields.io/badge/version-1.0.0-blue.svg)
[![PyPI package](https://img.shields.io/badge/pip%20install-encryptions-brightgreen)](https://pypi.org/project/encryptions/)
[![License](https://img.shields.io/github/license/BhargavLimbad786/Encryption)](https://github.com/BhargavLimbad786/Encryption/blob/main/LICENSE.txt)

<a href="https://github.com/BhargavLimbad786"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>



## Overview
  This script demonstrates cryptographic operations like AES encryption/decryption, RSA encryption/decryption, and hashing using Python's pycryptodome, base64, and hashlib library.

## Features
AES Encryption (ECB): Encrypts and decrypts data using AES in ECB mode.
RSA Key Pair Generation: Creates 2048-bit RSA keys.
RSA Encryption/Decryption: Uses PKCS1_OAEP padding for secure RSA operations.
Hashing: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.

## Dependencies 

    pip install -r requirements.txt

## Function Details

### AES Encryption/Decryption
AES is a Symmetric Encryption, AES is stand for Advanced Encryption Standard. it has many diffrent types like 128/192/256. it is used to transfer bulk of data it is less complex and faster to execute. It uses to secure file storage disk ensryption, VPNs, Communication Protocl like TLS, SSH etc..

    aes_encrypt_ecb(data, key)

        Encrypts plaintext using AES in ECB mode.

        Args:

            data (str): The plaintext to encrypt.

            key (bytes): A key of length 16, 24, or 32 bytes.

        Returns:

            Encrypted data (bytes).Function Details
        
    aes_decrypt_ecb(ciphertext, key)

        Decrypts AES-encrypted ciphertext in ECB mode.

        Args:

            ciphertext (bytes): The encrypted data.

            key (bytes):
                The decryption key.

        Returns:

            Decrypted plaintext (str).

### RSA Encryption/Decryption
RSA is symmetric Encryption. RSA stands for Rivest-Shamir-Adleman. It use to Secure key exchange, Digital Signatures and email encryption used with small sizes data.

    generate_rsa_keys()

        Generates a pair of RSA public and private keys.

        Returns:

            private_key (bytes): RSA private key.

            public_key (bytes): RSA public key.

    rsa_encrypt(plaintext, public_key)

        Encrypts plaintext using an RSA public key.

        Args:

            plaintext (str): The plaintext to encrypt.

            public_key (bytes): The RSA public key.

        Returns:

            Encrypted data (bytes).

    rsa_decrypt(encrypted_data, private_key)

        Decrypts RSA-encrypted data using a private key.

        Args:

            encrypted_data (bytes): The encrypted data.

            private_key (bytes): The RSA private key.

        Returns:

            Decrypted plaintext (str).

In here we are also using base64 encodig, It is used to Safely Transmit Data over network. Base64 is used to Encode text as Binary Email attachments, APIs


## All hashing functions:

md5 and sha1 is used in legacy Application and Non- critical integrity checks and less collision resistance. 

-> md5_hash(data): Generates an MD5 hash of the input data.

-> sha1_hash(data): Generates a SHA-1 hash.

SHA-224/256(Secure hash Algorithm) is used in Digital Signatures, Password Hashing and blockchain etc. it is communally used for data integrity because of it’s strange collision resistance.

-> sha224_hash(data): Generates a SHA-224 hash.

-> sha256_hash(data): Generates a SHA-256 hash.


SHA-384 is a cryptographic hash function from the SHA-2 family. It produces a 384-bit (48-byte) hash value. You can compute a SHA-384 hash in Python using the hashlib module.

-> sha384_hash(data): Generates a SHA-384 hash.

SHA-512 is a cryptographic hash function from the SHA-2 family that produces a 512-bit (64-byte) hash value. You can compute a SHA-512 hash in Python using the hashlib module.

-> sha512_hash(data): Generates a SHA-512 hash.

-> Args: data (str): Input string to hash.

-> Returns: Hash value (str).


## Outputs

    RSA: Encrypts and decrypts plaintext securely.
    AES: Encrypts and decrypts text using AES with a random key.
    Hashing: Generates cryptographic hashes for text.

## Security Notes

ECB mode leaks patterns; use safer modes like CBC or GCM for production.
This script is for educational purposes only.

## License

This project is licensed under the Apache2 reset License

## Usage

### Installation

```
pip install encryptions
```

### Asymmetric encryption and decryption

```Python

from encryptions.encryption import aes_encrypt_ecb,aes_decrypt_ecb,generate_rsa_keys,rsa_encrypt,rsa_decrypt,md5_hash,sha1_hash,sha224_hash,sha256_hash,sha384_hash,sha512_hash
from Crypto.Random import get_random_bytes
import base64

# Main Program
if __name__ == "__main__":
     # Original text to be encrypted and decrypted
    original_text = "This is a secret message that will be encrypted with RSA and AES."
    print("Original Text:", original_text)

    aes_key = get_random_bytes(16)

     # AES encryption with AES key
    encrypted_data_aes = aes_encrypt_ecb(original_text, aes_key)
    print("\n--- AES Encryption ---")
    print("Encrypted Text (Base64):", base64.b64encode(encrypted_data_aes).decode('utf-8')) #in here we are using base64 encoding technique. 

    # Decrypt the ciphertext using the AES key
    decrypted_text_aes = aes_decrypt_ecb(encrypted_data_aes, aes_key)
    print("\n--- AES Decryption ---")
    print("Decrypted Text AES:", decrypted_text_aes)

    print("---------------------------------------------------------------------------------------------")

    # Generate RSA keys (Public and Private)
    private_key, public_key = generate_rsa_keys()
    
    # Encrypt plaintext using RSA with public_key
    encrypted_data = rsa_encrypt(original_text, public_key)
    print("\n--- RSA Encryption ---")
    print("Encrypted Text (Base64):", base64.b64encode(encrypted_data).decode('utf-8'))

    # Decrypt ciphertext using RSA private_key
    decrypted_text = rsa_decrypt(encrypted_data, private_key)
    print("\n--- RSA Decryption ---")
    print("Decrypted Text:", decrypted_text)

    print("---------------------------------------------------------------------------------------------")

    # Hashing the original text
    print("\n--- Hashing Functions ---")
    print("MD5 Hash:", md5_hash(original_text))
    print("SHA-1 Hash:", sha1_hash(original_text))
    print("SHA-224 Hash:", sha224_hash(original_text))
    print("SHA-256 Hash:", sha256_hash(original_text))
    print("SHA-384 Hash:", sha384_hash(original_text))
    print("SHA-512 Hash:", sha512_hash(original_text))
```