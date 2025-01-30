# Encryption
<a href="https://github.com/BhargavLimbad786"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>

Overview

  This script demonstrates cryptographic operations like AES encryption/decryption, RSA encryption/decryption, and hashing using Python's pycryptodome, base64, and hashlib library.

Features

    AES Encryption (ECB): Encrypts and decrypts data using AES in ECB mode.
    RSA Key Pair Generation: Creates 2048-bit RSA keys.
    RSA Encryption/Decryption: Uses PKCS1_OAEP padding for secure RSA operations.
    Hashing: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.

Dependencies 

    pip install -r requirements.txt

to Run the script as a standalone program:

go to the encryption directory and run given command.

    python encryption.py

Function Details

    AES Encryption/Decryption

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

    RSA Encryption/Decryption

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

                 
All hashing functions:

    md5_hash(data): Generates an MD5 hash of the input data.

    sha1_hash(data): Generates a SHA-1 hash.

    sha224_hash(data): Generates a SHA-224 hash.

    sha256_hash(data): Generates a SHA-256 hash.

    sha384_hash(data): Generates a SHA-384 hash.

    sha512_hash(data): Generates a SHA-512 hash.

    Args: data (str): Input string to hash.

    Returns: Hash value (str).


Outputs

    RSA: Encrypts and decrypts plaintext securely.
    AES: Encrypts and decrypts text using AES with a random key.
    Hashing: Generates cryptographic hashes for text.

Security Notes

    ECB mode leaks patterns; use safer modes like CBC or GCM for production.
    This script is for educational purposes only.

License

    This project is licensed under the Apache2 reset License
