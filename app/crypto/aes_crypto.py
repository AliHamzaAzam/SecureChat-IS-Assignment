"""
AES-128-CBC encryption with PKCS#7 padding.

Algorithm: AES-128, Mode: CBC, Padding: PKCS#7, IV: Random 16 bytes
Ciphertext format: [16-byte IV] + [encrypted data]

Usage:
    key = b'0123456789abcdef'  # 16 bytes
    ct = aes_encrypt("Hello", key)
    pt = aes_decrypt(ct, key)
"""

from typing import Tuple
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding


# AES-128 key size (16 bytes = 128 bits)
AES_KEY_SIZE = 16
AES_BLOCK_SIZE = 128  # bits


def _apply_pkcs7_padding(data: bytes) -> bytes:
    """Apply PKCS#7 padding to data."""
    padder = crypto_padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def _remove_pkcs7_padding(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Raises: ValueError if padding invalid
    """
    unpadder = crypto_padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    try:
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    except Exception as e:
        raise ValueError(f"Invalid PKCS#7 padding: {e}")


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt string using AES-128-CBC with PKCS#7 padding.
    
    Args: plaintext, key (16 bytes)
    Returns: [16-byte IV] + [encrypted data]
    Raises: ValueError if key not 16 bytes
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode("utf-8")

    # Apply PKCS#7 padding
    padded_plaintext = _apply_pkcs7_padding(plaintext_bytes)

    # Generate random IV
    iv = secrets.token_bytes(AES_KEY_SIZE)

    # Create cipher and encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Prepend IV to ciphertext
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypt ciphertext using AES-128 CBC with PKCS#7 padding removal.
    
    Args: ciphertext ([IV] + [data]), key (16 bytes)
    Returns: Decrypted plaintext string
    Raises: ValueError if invalid key, data, or padding
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    if len(ciphertext) < AES_KEY_SIZE:
        raise ValueError(
            f"Ciphertext too short (minimum {AES_KEY_SIZE} bytes for IV), got {len(ciphertext)}"
        )

    # Extract IV and ciphertext
    iv = ciphertext[:AES_KEY_SIZE]
    encrypted_data = ciphertext[AES_KEY_SIZE:]

    # Create cipher and decrypt
    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

    # Remove PKCS#7 padding
    plaintext_bytes = _remove_pkcs7_padding(padded_plaintext)

    # Convert to string
    try:
        plaintext = plaintext_bytes.decode("utf-8")
        return plaintext
    except UnicodeDecodeError as e:
        raise ValueError(f"Decrypted data is not valid UTF-8: {e}")


def get_random_key() -> bytes:
    """Generate random 16-byte AES-128 key."""
    return secrets.token_bytes(AES_KEY_SIZE)
