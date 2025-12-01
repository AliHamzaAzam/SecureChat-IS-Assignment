"""
Diffie-Hellman key exchange using RFC 3526 Group 14 (2048-bit safe prime).

Protocol: Alice generates (a, A=g^a mod p), Bob generates (b, B=g^b mod p)
Shared secret: Ks = B^a mod p = A^b mod p
Session key: SHA256(Ks)[:16] (AES-128)
"""

from typing import Tuple
import secrets
from cryptography.hazmat.primitives import hashes


# RFC 3526 Group 14: 2048-bit safe prime
# This is a standard well-vetted prime used in many cryptographic protocols
# Source: https://datatracker.ietf.org/doc/html/rfc3526#section-3
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529070796966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

# Generator
G = 2

# Size of private keys in bits
PRIVATE_KEY_BITS = 256


def generate_dh_keypair() -> Tuple[int, int]:
    """
    Generate DH keypair: (private_key, public_key=g^private mod p).
    
    Returns: (256-bit private key, public key)
    """
    # Generate random private key (256 bits)
    private_key = secrets.randbits(PRIVATE_KEY_BITS)

    # Ensure private key is in valid range [2, p-2]
    # This is a security requirement for DH
    private_key = (private_key % (P - 3)) + 2

    # Compute public key: A = g^a mod p
    public_key = pow(G, private_key, P)

    return private_key, public_key


def compute_shared_secret(private_key: int, peer_public_key: int) -> bytes:
    """
    Compute shared secret and derive AES-128 key.
    
    Computes: Ks = peer_public_key^private_key mod p
    Derives: SHA256(Ks)[:16]
    
    Returns: 16-byte AES-128 session key
    Raises: ValueError if peer_public_key invalid
    """
    # Validate peer's public key
    if not isinstance(peer_public_key, int):
        raise ValueError("peer_public_key must be an integer")

    if peer_public_key < 2 or peer_public_key >= P:
        raise ValueError(f"peer_public_key must be in range [2, p-1], got {peer_public_key}")

    # Compute shared secret: Ks = peer_public_key^private_key mod p
    shared_secret = pow(peer_public_key, private_key, P)

    # Convert to big-endian bytes (256 bytes for 2048-bit prime)
    shared_secret_bytes = shared_secret.to_bytes(256, byteorder="big")

    # Derive session key using SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret_bytes)
    hash_result = digest.finalize()

    # Take first 16 bytes for AES-128 key
    session_key = hash_result[:16]

    return session_key


def validate_public_key(public_key: int) -> bool:
    """
    Validate that a public key is in the valid range.

    Args:
        public_key: Public key to validate (integer)

    Returns:
        bool: True if valid, False otherwise
    """
    if not isinstance(public_key, int):
        return False

    return 2 <= public_key < P


def get_dh_params() -> Tuple[int, int]:
    """
    Get the DH parameters (p, g).

    Returns:
        Tuple of (p: int, g: int)
    """
    return P, G


def get_prime_bit_length() -> int:
    """
    Get the bit length of the prime p.

    Returns:
        int: Bit length of prime p
    """
    return P.bit_length()
