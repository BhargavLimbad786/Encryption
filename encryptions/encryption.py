from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import hashlib
def aes_encrypt_ecb(data, key):
    """
    Encrypts the given data using AES encryption in ECB mode.
    It does not require an Initialization Vector (IV) or
    extra parameters, which makes it easy to implement.
    allows for parallel processing of each block thats why we use it.
    but it is only for educational purpose.
    Args:
        data (str): The plaintext data to encrypt.
        key (bytes): A 16, 24, or 32-byte key.
        
    Returns:
        bytes: The encrypted ciphertext.
    """
    if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
        raise ValueError("Key must be a bytes object of length 16, 24, or 32.")
    
    # Convert data to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, bytes):
        raise ValueError("Data must be a string or bytes object.")
    
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Encrypt the data with padding
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    return ciphertext


def aes_decrypt_ecb(ciphertext, key):
    """
    Decrypts AES-encrypted data in ECB mode.
    
    Args:
        ciphertext (bytes): The encrypted data.
        key (bytes): The decryption key.
        
    Returns:
        str: The decrypted plaintext.
    """
    if not isinstance(key, bytes) or len(key) not in [16, 24, 32]:
        raise ValueError("Key must be a bytes object of length 16, 24, or 32.")
    
    """
    MODE_ECB = 1        #: Electronic Code Book used for only for data that doesn't have 
                           repeating patterns. short and simple text.
    MODE_CBC = 2        #: Cipher-Block used for Chaining File encryption, disk encryption,
                           SSL/TLS, data storage.
    MODE_CFB = 3        #: Cipher Feedback used for Stream encryption, real-time data
    MODE_OFB = 5        #: Output Feedback used for Real-time traffic, VPNs, encrypted communications
    MODE_CTR = 6        #: Counter mode used for High-speed encryption, large datasets, parallel processing
    MODE_OPENPGP = 7    #: OpenPGP mode Used for secure email communication, file encryption,
                           document signing, and key exchange, ensuring confidentiality, authentication, and data integrity. 
    MODE_CCM = 8        #: Counter with CBC-MAC used when you need authenticated encryption with both 
                           confidentiality and integrity for data, typically in low-latency environments like network protocols 
                           and secure communications(Wi-Fi encryption, IoT devices).
    MODE_EAX = 9        #: Use AES EAX mode when you need authenticated encryption that provides 
                           both confidentiality and integrity for your data with high performance, while also ensuring 
                           that no additional data (like an IV or nonce) is reused.
    MODE_SIV = 10       #: Synthetic Initialization Vector used when you need authenticated encryption with a nonce reuse 
                           resilience and want to avoid potential security risks caused by reusing the nonce.
    MODE_GCM = 11       #: Galois Counter Mode when you need both encryption and integrity verification in high-performance 
                           applications, such as secure communication protocols (TLS, HTTPS) or disk encryption.
    MODE_OCB = 12       #: Offset Code Book used when you need authenticated encryption with high performance, 
                           providing both confidentiality and integrity in a single step, suitable for
                           high-speed applications like disk encryption and network protocols.
    """
    
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the data and remove padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    return plaintext.decode('utf-8')

# RSA Key Generation (Public and Private keys)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    return private_key, public_key

# RSA Encryption (Encrypt original plaintext with RSA public key)
def rsa_encrypt(plaintext, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    
    # Encrypt the plaintext
    encrypted_data = cipher.encrypt(plaintext.encode('utf-8'))
    return encrypted_data

def rsa_decrypt(encrypted_data, private_key):
    # RSA Decryption (Decrypt ciphertext with RSA private key)

    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    
    # Decrypt the ciphertext and decode back to string
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Hashing Functions
def md5_hash(data):
    """Generates an MD5 hash for the given data."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def sha1_hash(data):
    """Generates a SHA-1 hash for the given data."""
    return hashlib.sha1(data.encode('utf-8')).hexdigest()

def sha224_hash(data):
    """Generates a SHA-224 hash for the given data."""
    return hashlib.sha224(data.encode('utf-8')).hexdigest()

def sha256_hash(data):
    """Generates a SHA-256 hash for the given data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def sha384_hash(data):
    """Generates a SHA-384 hash for the given data."""
    return hashlib.sha384(data.encode('utf-8')).hexdigest()

def sha512_hash(data):
    """Generates a SHA-512 hash for the given data."""
    return hashlib.sha512(data.encode('utf-8')).hexdigest()

# Main Program
if __name__ == "__main__":
    # Original text to be encrypted and decrypted
    original_text = "This is a secret message that will be encrypted with RSA and AES."
    print("Original Text:", original_text)

    # Generate RSA keys (Public and Private)
    private_key, public_key = generate_rsa_keys()
    
    # Encrypt plaintext using RSA with public_key
    encrypted_data = rsa_encrypt(original_text, public_key)
    print("\n--- RSA Encryption 1 ---")
    print("Encrypted Text (Base64):", base64.b64encode(encrypted_data).decode('utf-8'))

    # Decrypt ciphertext using RSA private_key
    decrypted_text = rsa_decrypt(encrypted_data, private_key)
    print("\n--- RSA Decryption ---")
    print("Decrypted Text:", decrypted_text)

    print("---------------------------------------------------------------------------------------------")

    # Generate a random AES key (16 bytes)
    aes_key = get_random_bytes(16)
    
    # AES encryption with AES key
    encrypted_data_aes = aes_encrypt_ecb(original_text, aes_key)
    print("\n--- AES Encryption ---")
    print("Encrypted Text (Base64):", base64.b64encode(encrypted_data_aes).decode('utf-8'))

    # Decrypt the ciphertext using the AES key
    decrypted_text_aes = aes_decrypt_ecb(encrypted_data_aes, aes_key)
    print("\n--- AES Decryption ---")
    print("Decrypted Text AES:", decrypted_text_aes)

    print("---------------------------------------------------------------------------------------------")

    # Hashing the original text
    print("\n--- Hashing Functions ---")
    print("MD5 Hash:", md5_hash(original_text))
    print("SHA-1 Hash:", sha1_hash(original_text))
    print("SHA-224 Hash:", sha224_hash(original_text))
    print("SHA-256 Hash:", sha256_hash(original_text))
    print("SHA-384 Hash:", sha384_hash(original_text))
    print("SHA-512 Hash:", sha512_hash(original_text))

