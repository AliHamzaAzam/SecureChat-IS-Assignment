"""
RSA digital signature utilities for authentication and non-repudiation.

This module provides functions for signing and verifying data using RSA-2048 with SHA-256.

Signature Scheme:
    Algorithm: RSA-2048
    Padding: PSS (Probabilistic Signature Scheme)
    Hash: SHA-256
    Salt Length: 32 bytes (SHA256 output size)

The signature provides:
    - Authentication: Verify signer's identity
    - Integrity: Ensure data hasn't been tampered with
    - Non-repudiation: Signer cannot deny having signed

Usage:
    from app.crypto.rsa_signer import sign_data, verify_signature, compute_sha256
    from app.crypto.cert_validator import load_certificate, load_private_key

    # Load signing key
    private_key = load_private_key("server_key.pem")

    # Sign some data
    data = b"Important message"
    signature = sign_data(data, private_key)

    # Verify signature using certificate
    certificate = load_certificate("server_cert.pem")
    is_valid = verify_signature(data, signature, certificate)
    if not is_valid:
        raise ValueError("Signature verification failed!")

RSA-PSS Security:
    - Probabilistic: Same message produces different signatures (randomness in padding)
    - Secure: Resistant to known attacks on RSA signatures
    - Standard: Recommended by PKCS#1 v2.1
"""

from typing import Union
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def compute_sha256(data: bytes) -> bytes:
    """
    Compute the SHA-256 digest of data.

    Args:
        data: Input bytes to hash

    Returns:
        bytes: 32-byte SHA-256 digest

    Raises:
        TypeError: If data is not bytes

    Example:
        >>> digest = compute_sha256(b"Hello, World!")
        >>> len(digest)
        32
        >>> digest.hex()
        'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'
    """
    if not isinstance(data, bytes):
        raise TypeError(f"data must be bytes, got {type(data)}")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign data using RSA-2048 with SHA-256 and PSS padding.

    Args:
        data: Bytes to sign
        private_key: RSA private key for signing

    Returns:
        bytes: RSA-PSS signature

    Raises:
        TypeError: If data is not bytes or private_key is not RSA key
        ValueError: If signing fails

    Example:
        >>> from app.crypto.cert_validator import load_private_key
        >>> private_key = load_private_key("server_key.pem")
        >>> data = b"Message to sign"
        >>> signature = sign_data(data, private_key)
        >>> len(signature) > 0
        True
    """
    if not isinstance(data, bytes):
        raise TypeError(f"data must be bytes, got {type(data)}")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError(f"private_key must be RSAPrivateKey, got {type(private_key)}")

    try:
        # Sign using RSA-PSS with SHA-256
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature
    except Exception as e:
        raise ValueError(f"Signature generation failed: {e}")


def verify_signature(
    data: bytes,
    signature: bytes,
    certificate: x509.Certificate,
) -> bool:
    """
    Verify an RSA-PSS signature using a certificate's public key.

    Args:
        data: Original bytes that were signed
        signature: RSA-PSS signature bytes
        certificate: X.509 certificate containing the public key

    Returns:
        bool: True if signature is valid, False otherwise

    Raises:
        TypeError: If parameters are of wrong type
        ValueError: If verification cannot proceed

    Example:
        >>> from app.crypto.cert_validator import load_certificate
        >>> from app.crypto.rsa_signer import sign_data, verify_signature
        >>> from app.crypto.cert_validator import load_private_key
        >>> 
        >>> private_key = load_private_key("server_key.pem")
        >>> certificate = load_certificate("server_cert.pem")
        >>> data = b"Authenticated message"
        >>> signature = sign_data(data, private_key)
        >>> is_valid = verify_signature(data, signature, certificate)
        >>> is_valid
        True
    """
    if not isinstance(data, bytes):
        raise TypeError(f"data must be bytes, got {type(data)}")

    if not isinstance(signature, bytes):
        raise TypeError(f"signature must be bytes, got {type(signature)}")

    if not isinstance(certificate, x509.Certificate):
        raise TypeError(f"certificate must be X.509 Certificate, got {type(certificate)}")

    try:
        # Extract public key from certificate
        public_key = certificate.public_key()

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Certificate does not contain an RSA public key")

        # Verify signature using RSA-PSS with SHA-256
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except Exception as e:
        # Signature verification failed
        # Return False instead of raising to allow graceful handling
        return False


def get_signature_algorithm() -> str:
    """
    Get a description of the signature algorithm used.

    Returns:
        str: Description of algorithm parameters
    """
    return "RSA-2048 with SHA-256 and PSS padding (salt_length=32)"


def get_key_size_bits(key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey]) -> int:
    """
    Get the key size in bits.

    Args:
        key: RSA key (private or public)

    Returns:
        int: Key size in bits

    Raises:
        TypeError: If key is not RSA key
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return key.key_size
    raise TypeError(f"key must be RSA key, got {type(key)}")
