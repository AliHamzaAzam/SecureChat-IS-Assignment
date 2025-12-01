"""
RSA-2048 digital signatures with SHA-256 and PSS padding.

Provides: Authentication, Integrity, Non-repudiation
Algorithm: RSA-2048, Padding: PSS, Hash: SHA-256

Usage:
    sig = sign_data(data, private_key)
    is_valid = verify_signature(data, sig, certificate)
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
    
    Args: data, private_key
    Returns: RSA-PSS signature bytes
    Raises: TypeError, ValueError
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
    Verify RSA-PSS signature using certificate's public key.
    
    Args: data, signature, certificate
    Returns: True if valid, False otherwise
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


def verify_signature_with_pem(
    data: bytes,
    signature: bytes,
    certificate_pem: str,
) -> bool:
    """
    Verify an RSA-PSS signature using a certificate's public key (PEM string version).

    This is a convenience wrapper around verify_signature() that accepts a PEM string
    instead of an X.509 certificate object.

    Args:
        data: Original bytes that were signed
        signature: RSA-PSS signature bytes
        certificate_pem: X.509 certificate as PEM-encoded string

    Returns:
        bool: True if signature is valid, False otherwise

    Raises:
        ValueError: If the certificate PEM is invalid
    """
    from app.crypto.cert_validator import load_certificate_from_pem_string
    
    try:
        certificate = load_certificate_from_pem_string(certificate_pem)
        return verify_signature(data, signature, certificate)
    except Exception as e:
        raise ValueError(f"Failed to verify signature: {e}")


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
