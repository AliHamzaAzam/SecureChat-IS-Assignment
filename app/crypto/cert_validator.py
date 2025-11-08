"""
X.509 certificate validation utilities.

This module provides functions to:
- Load certificates and private keys from PEM files
- Validate certificate signatures against a CA certificate
- Check certificate expiration
- Generate certificate fingerprints
"""

from pathlib import Path
from datetime import datetime
from typing import Tuple, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtensionOID


def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.

    Args:
        cert_path: Path to the PEM-encoded certificate file

    Returns:
        Loaded X.509 certificate object

    Raises:
        FileNotFoundError: If the certificate file doesn't exist
        ValueError: If the file is not a valid PEM certificate
    """
    cert_file = Path(cert_path)
    
    if not cert_file.exists():
        raise FileNotFoundError(f"Certificate file not found: {cert_path}")
    
    try:
        cert_pem = cert_file.read_bytes()
        certificate = x509.load_pem_x509_certificate(cert_pem)
        return certificate
    except ValueError as e:
        raise ValueError(f"Invalid PEM certificate format: {e}")
    except Exception as e:
        raise ValueError(f"Error loading certificate: {e}")


def load_private_key(key_path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """
    Load a private key from a PEM file.

    Args:
        key_path: Path to the PEM-encoded private key file
        password: Optional password for encrypted keys (None for unencrypted)

    Returns:
        Loaded RSA private key object

    Raises:
        FileNotFoundError: If the key file doesn't exist
        ValueError: If the file is not a valid PEM private key
    """
    key_file = Path(key_path)
    
    if not key_file.exists():
        raise FileNotFoundError(f"Private key file not found: {key_path}")
    
    try:
        key_pem = key_file.read_bytes()
        private_key = load_pem_private_key(key_pem, password=password)
        
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Only RSA private keys are supported")
        
        return private_key
    except ValueError as e:
        raise ValueError(f"Invalid PEM private key format: {e}")
    except Exception as e:
        raise ValueError(f"Error loading private key: {e}")


def validate_certificate(cert: x509.Certificate, 
                        ca_cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
    """
    Validate an X.509 certificate against a CA certificate.

    This function checks:
    1. The certificate signature is valid (signed by the CA)
    2. The certificate is not expired (current time is within validity period)

    Args:
        cert: Certificate to validate
        ca_cert: CA certificate used to verify the signature

    Returns:
        Tuple of (is_valid: bool, error_message: str or None)
        - If valid: (True, None)
        - If invalid: (False, descriptive error message)
    """
    try:
        # Check certificate expiration
        now = datetime.utcnow()
        
        if now < cert.not_valid_before:
            return (False, f"Certificate not yet valid (valid from {cert.not_valid_before})")
        
        if now > cert.not_valid_after:
            return (False, f"Certificate has expired (valid until {cert.not_valid_after})")
        
        # Verify certificate signature with CA public key
        ca_public_key = ca_cert.public_key()
        
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            return (False, f"Certificate signature verification failed: {e}")
        
        return (True, None)
    
    except Exception as e:
        return (False, f"Certificate validation error: {e}")


def get_cert_fingerprint(cert: x509.Certificate) -> str:
    """
    Generate a SHA-256 fingerprint of a certificate.

    Args:
        cert: X.509 certificate

    Returns:
        Hex-encoded SHA-256 fingerprint of the certificate

    Example:
        >>> cert = load_certificate("server_cert.pem")
        >>> fingerprint = get_cert_fingerprint(cert)
        >>> print(fingerprint)
        a1b2c3d4e5f6...
    """
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashes.Hash(hashes.SHA256())
    fingerprint.update(cert_der)
    return fingerprint.finalize().hex()


def get_cert_subject_cn(cert: x509.Certificate) -> Optional[str]:
    """
    Extract the Common Name (CN) from a certificate's subject.

    Args:
        cert: X.509 certificate

    Returns:
        Common Name string if found, None otherwise
    """
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
        return None
    except Exception:
        return None


def get_cert_san(cert: x509.Certificate) -> list:
    """
    Extract Subject Alternative Names (SAN) from a certificate.

    Args:
        cert: X.509 certificate

    Returns:
        List of DNS names from the SAN extension, or empty list if not present
    """
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = san_ext.value
        dns_names = [name.value for name in san_list if isinstance(name, x509.DNSName)]
        return dns_names
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def is_ca_certificate(cert: x509.Certificate) -> bool:
    """
    Check if a certificate is marked as a CA certificate.

    Args:
        cert: X.509 certificate

    Returns:
        True if certificate has Basic Constraints with CA=TRUE, False otherwise
    """
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return basic_constraints.ca
    except x509.ExtensionNotFound:
        return False
    except Exception:
        return False
