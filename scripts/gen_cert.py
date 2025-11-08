#!/usr/bin/env python3
"""
Issue a certificate signed by the Root CA.

This script:
- Loads the CA private key and certificate from certs/ca_key.pem and certs/ca_cert.pem
- Generates a 2048-bit RSA key pair for the entity (client or server)
- Creates a Certificate Signing Request (CSR)
- Signs the CSR with the CA private key to issue an X.509 certificate
- Saves the entity private key and certificate to PEM files

Usage:
    python scripts/gen_cert.py --name server --cn server.local
    python scripts/gen_cert.py --name client --cn client.local
    python scripts/gen_cert.py --name server --cn server.local --out certs/custom
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
)


def load_ca_key_and_cert(certs_dir: Path) -> tuple:
    """
    Load the CA private key and certificate from PEM files.

    Args:
        certs_dir: Directory containing ca_key.pem and ca_cert.pem

    Returns:
        Tuple of (ca_private_key, ca_certificate)

    Raises:
        FileNotFoundError: If CA files don't exist
        ValueError: If files can't be parsed
    """
    key_path = certs_dir / "ca_key.pem"
    cert_path = certs_dir / "ca_cert.pem"

    if not key_path.exists():
        raise FileNotFoundError(f"CA private key not found: {key_path}")
    if not cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {cert_path}")

    print(f"[*] Loading CA private key from {key_path}...")
    try:
        ca_key_pem = key_path.read_bytes()
        ca_private_key = load_pem_private_key(ca_key_pem, password=None)
        print("[✓] CA private key loaded")
    except Exception as e:
        raise ValueError(f"Failed to load CA private key: {e}")

    print(f"[*] Loading CA certificate from {cert_path}...")
    try:
        ca_cert_pem = cert_path.read_bytes()
        ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem)
        print("[✓] CA certificate loaded")
    except Exception as e:
        raise ValueError(f"Failed to load CA certificate: {e}")

    return ca_private_key, ca_certificate


def generate_entity_key() -> rsa.RSAPrivateKey:
    """
    Generate a 2048-bit RSA private key for the entity.

    Returns:
        RSA private key object
    """
    print("[*] Generating 2048-bit RSA private key for entity...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    print("[✓] Entity RSA private key generated")
    return private_key


def create_csr(entity_key: rsa.RSAPrivateKey, common_name: str) -> x509.CertificateSigningRequest:
    """
    Create a Certificate Signing Request (CSR).

    Args:
        entity_key: Entity's RSA private key
        common_name: Common Name (CN) for the certificate

    Returns:
        Certificate Signing Request object
    """
    print(f"[*] Creating Certificate Signing Request (CSR)...")
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name)]
            ),
            critical=False,
        )
        .sign(entity_key, hashes.SHA256())
    )

    print("[✓] CSR created")
    return csr


def sign_csr(csr: x509.CertificateSigningRequest,
             ca_private_key,
             ca_certificate: x509.Certificate) -> x509.Certificate:
    """
    Sign a CSR with the CA private key to issue a certificate.

    Args:
        csr: Certificate Signing Request to sign
        ca_private_key: CA's RSA private key
        ca_certificate: CA's X.509 certificate

    Returns:
        Signed X.509 certificate
    """
    print("[*] Signing CSR with CA private key...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            ),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    print("[✓] Certificate signed by CA")
    return cert


def save_entity_files(entity_key: rsa.RSAPrivateKey,
                      certificate: x509.Certificate,
                      name: str,
                      certs_dir: Path) -> None:
    """
    Save entity private key and certificate to PEM files.

    Args:
        entity_key: Entity's RSA private key
        certificate: Signed X.509 certificate
        name: Name of the entity (e.g., 'server', 'client')
        certs_dir: Directory to save certificate files
    """
    certs_dir.mkdir(parents=True, exist_ok=True)

    # Save private key
    key_path = certs_dir / f"{name}_key.pem"
    print(f"[*] Saving entity private key to {key_path}...")
    try:
        key_pem = entity_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)  # Restrict permissions on private key
        print(f"[✓] Entity private key saved to {key_path}")
    except IOError as e:
        print(f"[✗] Error saving private key: {e}", file=sys.stderr)
        raise

    # Save certificate
    cert_path = certs_dir / f"{name}_cert.pem"
    print(f"[*] Saving entity certificate to {cert_path}...")
    try:
        cert_pem = certificate.public_bytes(Encoding.PEM)
        cert_path.write_bytes(cert_pem)
        print(f"[✓] Entity certificate saved to {cert_path}")
    except IOError as e:
        print(f"[✗] Error saving certificate: {e}", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Issue a certificate signed by the Root CA"
    )
    parser.add_argument(
        "--name",
        required=True,
        help="Name of the entity (e.g., 'server', 'client')",
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (CN) for the certificate (e.g., 'server.local')",
    )
    parser.add_argument(
        "--out",
        default="certs",
        help="Output directory for certificate files (default: certs)",
    )
    parser.add_argument(
        "--ca-dir",
        default="certs",
        help="Directory containing CA files (default: certs)",
    )

    args = parser.parse_args()
    certs_dir = Path(args.out)
    ca_dir = Path(args.ca_dir)

    try:
        print("\n" + "=" * 60)
        print("Certificate Issuance by Root CA")
        print("=" * 60)
        print(f"[*] Entity Name: {args.name}")
        print(f"[*] Common Name: {args.cn}")
        print(f"[*] Output directory: {certs_dir}")
        print(f"[*] CA directory: {ca_dir}")
        print()

        # Load CA
        ca_private_key, ca_certificate = load_ca_key_and_cert(ca_dir)

        # Generate entity key
        entity_key = generate_entity_key()

        # Create CSR
        csr = create_csr(entity_key, args.cn)

        # Sign CSR
        certificate = sign_csr(csr, ca_private_key, ca_certificate)

        # Save files
        save_entity_files(entity_key, certificate, args.name, certs_dir)

        # Print certificate info
        print()
        print("[*] Certificate Details:")
        print(f"    Serial Number: {certificate.serial_number}")
        print(f"    Valid From: {certificate.not_valid_before}")
        print(f"    Valid To: {certificate.not_valid_after}")
        print(f"    Issuer: {certificate.issuer.rfc4514_string()}")
        print(f"    Subject: {certificate.subject.rfc4514_string()}")
        print()
        print("=" * 60)
        print(f"[✓] Certificate issuance completed successfully!")
        print("=" * 60)
        print()

    except FileNotFoundError as e:
        print(f"\n[✗] File Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\n[✗] Validation Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[✗] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
