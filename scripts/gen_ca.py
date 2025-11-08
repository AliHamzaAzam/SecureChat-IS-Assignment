#!/usr/bin/env python3
"""
Generate a self-signed Root Certificate Authority (CA).

This script creates:
- A 2048-bit RSA private key
- A self-signed X.509 certificate valid for 365 days
- Saves both to certs/ca_key.pem and certs/ca_cert.pem

Usage:
    python scripts/gen_ca.py [--name "CA Name"]
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)


def generate_ca(ca_name: str = "SecureChat Root CA") -> tuple:
    """
    Generate a self-signed root CA certificate and private key.

    Args:
        ca_name: Common Name (CN) for the CA certificate

    Returns:
        Tuple of (private_key, certificate)
    """
    print(f"[*] Generating 2048-bit RSA private key for CA...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    print("[✓] RSA private key generated")

    print(f"[*] Creating self-signed X.509 certificate...")
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
            x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    print("[✓] Self-signed certificate created")
    return private_key, cert


def save_ca_files(private_key, certificate, certs_dir: Path) -> None:
    """
    Save CA private key and certificate to PEM files.

    Args:
        private_key: RSA private key object
        certificate: X.509 certificate object
        certs_dir: Directory to save certificate files
    """
    certs_dir.mkdir(parents=True, exist_ok=True)

    # Save private key
    key_path = certs_dir / "ca_key.pem"
    print(f"[*] Saving CA private key to {key_path}...")
    try:
        key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)  # Restrict permissions on private key
        print(f"[✓] CA private key saved to {key_path}")
    except IOError as e:
        print(f"[✗] Error saving private key: {e}", file=sys.stderr)
        raise

    # Save certificate
    cert_path = certs_dir / "ca_cert.pem"
    print(f"[*] Saving CA certificate to {cert_path}...")
    try:
        cert_pem = certificate.public_bytes(Encoding.PEM)
        cert_path.write_bytes(cert_pem)
        print(f"[✓] CA certificate saved to {cert_path}")
    except IOError as e:
        print(f"[✗] Error saving certificate: {e}", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed Root Certificate Authority"
    )
    parser.add_argument(
        "--name",
        default="SecureChat Root CA",
        help="Common Name (CN) for the CA certificate (default: SecureChat Root CA)",
    )
    parser.add_argument(
        "--out",
        default="certs",
        help="Output directory for certificate files (default: certs)",
    )

    args = parser.parse_args()
    certs_dir = Path(args.out)

    try:
        print("\n" + "=" * 60)
        print("SecureChat Root CA Generation")
        print("=" * 60)
        print(f"[*] CA Name: {args.name}")
        print(f"[*] Output directory: {certs_dir}")
        print()

        # Generate CA
        private_key, certificate = generate_ca(args.name)

        # Save files
        save_ca_files(private_key, certificate, certs_dir)

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
        print("[✓] Root CA generation completed successfully!")
        print("=" * 60)
        print()

    except Exception as e:
        print(f"\n[✗] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
