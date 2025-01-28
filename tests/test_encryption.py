import unittest
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from encryptions import (
    aes_encrypt_ecb,
    aes_decrypt_ecb,
    rsa_encrypt,
    rsa_decrypt,
    md5_hash,
    sha1_hash,
    sha224_hash,
    sha256_hash,
    sha384_hash,
    sha512_hash,
    generate_rsa_keys
)
import base64

class TestCryptoFunctions(unittest.TestCase):

    def test_aes_encrypt_decrypt_ecb(self):
        """Test AES encryption and decryption in ECB mode."""
        data = "This is a secret message"
        key = get_random_bytes(16)  # AES key of 16 bytes
        
        # Encrypt the data
        encrypted = aes_encrypt_ecb(data, key)
        
        # Decrypt the data
        decrypted = aes_decrypt_ecb(encrypted, key)
        
        # Assert that the decrypted data matches the original plaintext
        self.assertEqual(data, decrypted)

    def test_aes_invalid_key_length(self):
        """Test invalid key length for AES encryption."""
        data = "Invalid key"
        
        # Test with an invalid key length (e.g., 10 bytes)
        with self.assertRaises(ValueError):
            aes_encrypt_ecb(data, get_random_bytes(10))

    def test_rsa_encrypt_decrypt(self):
        """Test RSA encryption and decryption."""
        original_text = "This is a secret message for RSA"
        
        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        
        # Encrypt the text using RSA public key
        encrypted_data = rsa_encrypt(original_text, public_key)
        
        # Decrypt the text using RSA private key
        decrypted_text = rsa_decrypt(encrypted_data, private_key)
        
        # Assert that the decrypted text matches the original
        self.assertEqual(original_text, decrypted_text)

    def test_rsa_invalid_decrypt(self):
        """Test RSA decryption with an incorrect private key."""
        original_text = "This is a secret message for RSA"
        
        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        
        # Encrypt the text using RSA public key
        encrypted_data = rsa_encrypt(original_text, public_key)
        
        # Generate a different private key
        different_private_key, _ = generate_rsa_keys()
        
        # Test decryption with a wrong private key
        with self.assertRaises(ValueError):
            rsa_decrypt(encrypted_data, different_private_key)

    def test_hash_functions(self):
        """Test hashing functions."""
        data = "This is some data to hash"
        
        # Test MD5 hash
        md5_result = md5_hash(data)
        self.assertEqual(len(md5_result), 32)  # MD5 is always 32 characters
        
        # Test SHA-1 hash
        sha1_result = sha1_hash(data)
        self.assertEqual(len(sha1_result), 40)  # SHA-1 is always 40 characters
        
        # Test SHA-224 hash
        sha224_result = sha224_hash(data)
        self.assertEqual(len(sha224_result), 56)  # SHA-224 is always 56 characters
        
        # Test SHA-256 hash
        sha256_result = sha256_hash(data)
        self.assertEqual(len(sha256_result), 64)  # SHA-256 is always 64 characters
        
        # Test SHA-384 hash
        sha384_result = sha384_hash(data)
        self.assertEqual(len(sha384_result), 96)  # SHA-384 is always 96 characters
        
        # Test SHA-512 hash
        sha512_result = sha512_hash(data)
        self.assertEqual(len(sha512_result), 128)  # SHA-512 is always 128 characters

if __name__ == "__main__":
    unittest.main()
