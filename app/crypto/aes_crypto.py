"""
AES-128 encryption utilities with PKCS#7 padding.

This module provides functions for symmetric encryption/decryption using:
- Algorithm: AES-128 (128-bit key)
- Mode: CBC (Cipher Block Chaining)
- Padding: PKCS#7
- IV: Random 16 bytes prepended to ciphertext

PKCS#7 Padding:
    Adds n bytes of value n to the plaintext, where n is the number of padding bytes needed.
    For example, if 5 bytes of padding are needed, 5 bytes of value 0x05 are appended.

Usage:
    from app.crypto.aes_crypto import aes_encrypt, aes_decrypt

    # Encrypt a message
    key = b'0123456789abcdef'  # 16-byte key for AES-128
    plaintext = "Hello, World!"
    ciphertext = aes_encrypt(plaintext, key)

    # Decrypt the message
    plaintext_recovered = aes_decrypt(ciphertext, key)
    assert plaintext == plaintext_recovered

Note:
    - Key must be exactly 16 bytes (128 bits)
    - IV is randomly generated for each encryption (ensures ciphertexts differ)
    - Ciphertext format: [16-byte IV] + [encrypted data]
"""

from typing import Tuple
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as crypto_padding


# AES-128 key size (16 bytes = 128 bits)
AES_KEY_SIZE = 16
AES_BLOCK_SIZE = 128  # bits


def _apply_pkcs7_padding(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding to data.

    Args:
        data: Input bytes to pad

    Returns:
        Padded bytes according to PKCS#7

    Example:
        >>> _apply_pkcs7_padding(b"hello")  # 5 bytes, need 11 bytes padding
        b"hello" + b"\x0b" * 11
    """
    padder = crypto_padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def _remove_pkcs7_padding(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data.

    Args:
        data: Padded bytes

    Returns:
        Unpadded bytes

    Raises:
        ValueError: If padding is invalid
    """
    unpadder = crypto_padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    try:
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data
    except Exception as e:
        raise ValueError(f"Invalid PKCS#7 padding: {e}")


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 CBC with PKCS#7 padding.

    Args:
        plaintext: String to encrypt
        key: 16-byte AES-128 key

    Returns:
        bytes: [16-byte IV] + [encrypted data]

    Raises:
        ValueError: If key is not 16 bytes

    Example:
        >>> key = b'0123456789abcdef'  # 16 bytes
        >>> plaintext = "Hello, World!"
        >>> ciphertext = aes_encrypt(plaintext, key)
        >>> len(ciphertext) > len(plaintext)  # Includes IV and padding
        True
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

    Args:
        ciphertext: bytes in format [16-byte IV] + [encrypted data]
        key: 16-byte AES-128 key

    Returns:
        str: Decrypted plaintext

    Raises:
        ValueError: If key is not 16 bytes, ciphertext too short, or padding invalid

    Example:
        >>> key = b'0123456789abcdef'
        >>> ciphertext = aes_encrypt("Secret message", key)
        >>> plaintext = aes_decrypt(ciphertext, key)
        >>> plaintext
        'Secret message'
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
    """
    Generate a random 16-byte AES-128 key.

    Returns:
        bytes: Random 128-bit key

    Example:
        >>> key = get_random_key()
        >>> len(key)
        16
    """
    return secrets.token_bytes(AES_KEY_SIZE)
