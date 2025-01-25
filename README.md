Overview

  This script demonstrates cryptographic operations like AES encryption/decryption, RSA encryption/decryption, and hashing using     Python's pycryptodome, base64, and hashlib library.

Features

    AES Encryption (ECB): Encrypts and decrypts data using AES in ECB mode.
    RSA Key Pair Generation: Creates 2048-bit RSA keys.
    RSA Encryption/Decryption: Uses PKCS1_OAEP padding for secure RSA operations.
    Hashing: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.

Dependencies

    check the given requirements.txt file for all Dependencies and used it for your script.

Installation

    pip install pycryptodome

to Run the script as a standalone program:

    python script_name.py

Outputs

    RSA: Encrypts and decrypts plaintext securely.
    AES: Encrypts and decrypts text using AES with a random key.
    Hashing: Generates cryptographic hashes for text.

Security Notes

    ECB mode leaks patterns; use safer modes like CBC or GCM for production.
    This script is for educational purposes only.

License

    This project is licensed under the MIT License.

