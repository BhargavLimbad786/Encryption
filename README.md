Overview

  This script demonstrates cryptographic operations like AES encryption/decryption, RSA encryption/decryption, and hashing using     Python's pycryptodome, base64, and hashlib library.

Features

    AES Encryption (ECB): Encrypts and decrypts data using AES in ECB mode.
    RSA Key Pair Generation: Creates 2048-bit RSA keys.
    RSA Encryption/Decryption: Uses PKCS1_OAEP padding for secure RSA operations.
    Hashing: Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512.

Dependencies

    Python 3.6 or later
    bcrypt==4.2.1
    certifi==2024.12.14
    cffi==1.17.1
    charset-normalizer==3.4.1
    crypto==1.4.1
    cryptography==44.0.0
    idna==3.10
    Naked==0.1.32
    pbkdf2==1.3
    pyaes==1.6.1
    pycparser==2.22
    pycryptodome==3.21.0
    PyYAML==6.0.2
    requests==2.32.3
    shellescape==3.8.1
    urllib3==2.3.0

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

