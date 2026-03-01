# crypto/aes_crypto.py

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


BLOCK_SIZE = 16  # AES block size


# ------------------------------------------------
# AES ENCRYPT
# ------------------------------------------------
def aes_encrypt(data_bytes: bytes):
    """
    Encrypts data using AES-256-CBC
    Returns: encrypted_data, aes_key, iv
    """
    aes_key = os.urandom(32)   # 256-bit key
    iv = os.urandom(16)        # 128-bit IV

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, aes_key, iv


# ------------------------------------------------
# AES DECRYPT (supports old + new storage format)
# ------------------------------------------------
def aes_decrypt(encrypted_blob, key):
    try:
        # New format: iv + ciphertext
        iv = encrypted_blob[:16]
        ciphertext = encrypted_blob[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plain) + unpadder.finalize()

    except Exception:
        # Old format: ciphertext + iv
        iv = encrypted_blob[-16:]
        ciphertext = encrypted_blob[:-16]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plain) + unpadder.finalize()
