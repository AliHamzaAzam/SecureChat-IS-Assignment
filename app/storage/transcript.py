"""
Append-only transcript logging for non-repudiation.

This module provides secure audit logging of encrypted chat sessions.
Each message (sent or received) is logged in append-only format with:
- Direction (SENT/RECV)
- Sequence number
- Timestamp
- Encrypted ciphertext (base64)
- Digital signature (base64)
- Peer certificate fingerprint (SHA-256)

Transcript files are stored in transcripts/{username}_session_{timestamp}.log
and use atomic append operations to prevent tampering.

Usage:
    from app.storage.transcript import write_transcript_entry, get_cert_fingerprint
    
    # Write a sent message entry
    write_transcript_entry(
        username="alice",
        direction="SENT",
        seqno=1,
        ts=1699563900000,
        ct_b64="...",
        sig_b64="...",
        peer_cert_pem="-----BEGIN CERTIFICATE..."
    )
"""

import os
import logging
from pathlib import Path
from datetime import datetime

try:
    from app.crypto.cert_validator import load_certificate_from_pem_string, get_cert_fingerprint
except ImportError:
    # Fallback if imports fail - functions will raise informative errors
    pass


logger = logging.getLogger(__name__)

# Transcripts directory
TRANSCRIPTS_DIR = Path(__file__).parent.parent.parent / "transcripts"


def get_cert_fingerprint_pem(cert_pem: str) -> str:
    """
    Get SHA-256 fingerprint of a PEM-encoded certificate.
    
    Args:
        cert_pem: PEM-encoded certificate string
        
    Returns:
        Hex-encoded SHA-256 fingerprint (64 characters)
        
    Raises:
        ValueError: If certificate cannot be parsed
    """
    try:
        cert = load_certificate_from_pem_string(cert_pem)
        return get_cert_fingerprint(cert)
    except Exception as e:
        logger.error(f"Failed to get certificate fingerprint: {e}")
        raise ValueError(f"Invalid certificate: {e}")


def ensure_transcripts_dir():
    """
    Create transcripts/ directory if it doesn't exist.
    
    This is called on first transcript write for a session.
    Uses Path.mkdir() with exist_ok=True for thread-safety.
    """
    try:
        TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Transcripts directory ensured: {TRANSCRIPTS_DIR}")
    except OSError as e:
        logger.error(f"Failed to create transcripts directory: {e}")
        raise


def get_session_transcript_path(username: str, session_ts: int = None) -> Path:
    """
    Get the file path for a chat session transcript.
    
    Filename format: transcripts/{username}_session_{timestamp}.log
    
    Args:
        username: Authenticated username
        session_ts: Session start timestamp (ms since epoch). If None, uses current time.
        
    Returns:
        Path object to transcript file
        
    Example:
        >>> path = get_session_transcript_path("alice", 1699563900000)
        >>> print(path)
        Path("/Users/.../SecureChat-IS-Assignment/transcripts/alice_session_1699563900000.log")
    """
    if session_ts is None:
        session_ts = int(datetime.now().timestamp() * 1000)
    
    filename = f"{username}_session_{session_ts}.log"
    return TRANSCRIPTS_DIR / filename


def write_transcript_entry(username: str, direction: str, seqno: int, ts: int,
                          ct_b64: str, sig_b64: str, peer_cert_pem: str,
                          session_ts: int = None):
    """
    Write an atomic transcript entry for a sent or received message.
    
    Format: "DIRECTION|seqno|ts|ct_b64|sig_b64|peer_fingerprint\n"
    
    Ensures:
    - Atomic append operation (file opened in 'a' mode)
    - Automatic flush after write
    - Directory creation on first write
    - Thread-safe file operations
    
    Args:
        username: Authenticated username (directory owner)
        direction: "SENT" or "RECV" - message direction
        seqno: Sequence number (monotonic counter per direction)
        ts: Timestamp in milliseconds since epoch
        ct_b64: Base64-encoded ciphertext
        sig_b64: Base64-encoded RSA-PSS signature
        peer_cert_pem: PEM-encoded peer certificate for fingerprinting
        session_ts: Session start timestamp (ms). If None, uses current time.
        
    Returns:
        Path to transcript file (for verification/logging)
        
    Raises:
        ValueError: If direction invalid or cert parsing fails
        OSError: If file I/O fails
        
    Example:
        >>> path = write_transcript_entry(
        ...     username="alice",
        ...     direction="SENT",
        ...     seqno=1,
        ...     ts=1699563900000,
        ...     ct_b64="abc123==",
        ...     sig_b64="def456==",
        ...     peer_cert_pem="-----BEGIN CERTIFICATE..."
        ... )
        >>> print(f"Logged to {path}")
    """
    # Validate direction
    direction = direction.upper()
    if direction not in ("SENT", "RECV"):
        raise ValueError(f"Invalid direction: {direction}. Must be 'SENT' or 'RECV'")
    
    # Get certificate fingerprint
    try:
        peer_fp = get_cert_fingerprint_pem(peer_cert_pem)
    except Exception as e:
        logger.error(f"Failed to extract peer certificate fingerprint: {e}")
        raise
    
    # Ensure transcripts directory exists
    try:
        ensure_transcripts_dir()
    except OSError as e:
        logger.error(f"Cannot write transcript: {e}")
        raise
    
    # Get transcript file path
    transcript_path = get_session_transcript_path(username, session_ts)
    
    # Format entry: DIRECTION|seqno|ts|ct_b64|sig_b64|peer_fp
    entry = f"{direction}|{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fp}\n"
    
    # Atomic append (open in 'a' mode for append-only semantics)
    try:
        with open(transcript_path, 'a') as f:
            f.write(entry)
            f.flush()  # Ensure written to disk
        
        logger.debug(f"Transcript entry written: {transcript_path} ({direction} seqno={seqno})")
        return transcript_path
        
    except IOError as e:
        logger.error(f"Failed to write transcript entry: {e}")
        raise


def read_transcript(username: str, session_ts: int = None) -> list:
    """
    Read all entries from a session transcript file.
    
    Returns list of dicts: [
        {
            "direction": "SENT|RECV",
            "seqno": int,
            "ts": int,
            "ct_b64": str,
            "sig_b64": str,
            "peer_fp": str
        },
        ...
    ]
    
    Args:
        username: Username
        session_ts: Session start timestamp (ms). If None, uses current time.
        
    Returns:
        List of parsed transcript entries, or empty list if file doesn't exist
        
    Raises:
        ValueError: If a line cannot be parsed
    """
    transcript_path = get_session_transcript_path(username, session_ts)
    
    if not transcript_path.exists():
        logger.debug(f"Transcript file not found: {transcript_path}")
        return []
    
    entries = []
    try:
        with open(transcript_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) != 6:
                    raise ValueError(
                        f"Invalid transcript format at line {line_num}: "
                        f"expected 6 fields, got {len(parts)}"
                    )
                
                direction, seqno_str, ts_str, ct_b64, sig_b64, peer_fp = parts
                
                try:
                    seqno = int(seqno_str)
                    ts = int(ts_str)
                except ValueError as e:
                    raise ValueError(
                        f"Invalid numeric field at line {line_num}: {e}"
                    )
                
                entries.append({
                    "direction": direction,
                    "seqno": seqno,
                    "ts": ts,
                    "ct_b64": ct_b64,
                    "sig_b64": sig_b64,
                    "peer_fp": peer_fp
                })
        
        logger.debug(f"Read {len(entries)} entries from {transcript_path}")
        return entries
        
    except Exception as e:
        logger.error(f"Failed to read transcript: {e}")
        raise


def compute_transcript_hash(username: str, session_ts: int = None) -> str:
    """
    Compute SHA-256 hash of all transcript entries up to current point.
    
    Used for generating non-repudiation receipts signed by session participant.
    Hash includes all SENT and RECV entries in order.
    
    Args:
        username: Username
        session_ts: Session start timestamp (ms)
        
    Returns:
        Hex-encoded SHA-256 hash of concatenated transcript lines
        
    Example:
        >>> receipt_hash = compute_transcript_hash("alice")
        >>> print(receipt_hash)
        "a1b2c3d4e5f6..."
    """
    import hashlib
    
    entries = read_transcript(username, session_ts)
    
    # Concatenate all lines in order
    transcript_data = ""
    for entry in entries:
        line = (
            f"{entry['direction']}|{entry['seqno']}|{entry['ts']}|"
            f"{entry['ct_b64']}|{entry['sig_b64']}|{entry['peer_fp']}\n"
        )
        transcript_data += line
    
    # Hash the transcript
    hash_obj = hashlib.sha256()
    hash_obj.update(transcript_data.encode('utf-8'))
    
    return hash_obj.hexdigest()


def generate_session_receipt(username: str, private_key_pem: str, peer_type: str,
                            session_ts: int = None) -> dict:
    """
    Generate a signed session receipt for non-repudiation.
    
    Computes SHA-256 hash of entire transcript, signs with private key,
    and creates SessionReceipt containing:
    - Type: "receipt"
    - Peer type: "client" or "server"
    - First/last sequence numbers
    - Transcript SHA-256 hash
    - RSA-PSS signature
    
    Args:
        username: Authenticated username
        private_key_pem: PEM-encoded RSA private key for signing
        peer_type: "client" or "server" indicating signer's role
        session_ts: Session start timestamp (ms). If None, uses current time.
        
    Returns:
        Dict with receipt data:
        {
            "type": "receipt",
            "peer": "client" or "server",
            "username": username,
            "first_seq": int (lowest seqno across all directions),
            "last_seq": int (highest seqno across all directions),
            "transcript_sha256": str (hex-encoded hash),
            "sig": str (base64-encoded RSA-PSS signature)
        }
        
    Raises:
        ValueError: If transcript is empty or peer_type invalid
        Exception: If signing fails
        
    Example:
        >>> receipt = generate_session_receipt(
        ...     username="alice",
        ...     private_key_pem=client_key,
        ...     peer_type="client"
        ... )
        >>> print(receipt["type"])
        "receipt"
    """
    import base64
    
    # Validate peer type
    peer_type = peer_type.lower()
    if peer_type not in ("client", "server"):
        raise ValueError(f"Invalid peer_type: {peer_type}. Must be 'client' or 'server'")
    
    # Read transcript entries
    entries = read_transcript(username, session_ts)
    
    if not entries:
        raise ValueError(f"Cannot generate receipt: no transcript entries for {username}")
    
    # Compute transcript hash
    transcript_hash = compute_transcript_hash(username, session_ts)
    
    # Extract min/max sequence numbers
    seqnos = [entry["seqno"] for entry in entries]
    first_seq = min(seqnos)
    last_seq = max(seqnos)
    
    # Load private key and sign
    try:
        from app.crypto.cert_validator import load_private_key_from_pem_string
        from app.crypto.rsa_signer import sign_data
    except ImportError:
        raise RuntimeError("Cannot import crypto modules for signing")
    
    try:
        private_key = load_private_key_from_pem_string(private_key_pem)
    except Exception as e:
        logger.error(f"Failed to load private key for receipt signing: {e}")
        raise
    
    try:
        # Sign the transcript hash
        signature_bytes = sign_data(
            transcript_hash.encode('utf-8'),
            private_key
        )
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to sign receipt: {e}")
        raise
    
    # Create receipt dict
    receipt = {
        "type": "receipt",
        "peer": peer_type,
        "username": username,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": signature_b64
    }
    
    logger.debug(f"Generated session receipt for {username} (seqno {first_seq}-{last_seq})")
    return receipt


def save_session_receipt(receipt: dict, username: str, session_ts: int = None) -> Path:
    """
    Save session receipt to disk as JSON file.
    
    Filename: transcripts/{username}_receipt_{timestamp}.json
    
    Args:
        receipt: Receipt dict from generate_session_receipt()
        username: Authenticated username
        session_ts: Session start timestamp (ms). If None, uses current time.
        
    Returns:
        Path to saved receipt file
        
    Raises:
        OSError: If file write fails
    """
    import json
    
    if session_ts is None:
        session_ts = int(datetime.now().timestamp() * 1000)
    
    # Ensure transcripts directory exists
    try:
        ensure_transcripts_dir()
    except OSError as e:
        logger.error(f"Cannot save receipt: {e}")
        raise
    
    # Create receipt filename
    receipt_filename = f"{username}_receipt_{session_ts}.json"
    receipt_path = TRANSCRIPTS_DIR / receipt_filename
    
    # Write receipt to disk
    try:
        with open(receipt_path, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        logger.info(f"Session receipt saved: {receipt_path}")
        return receipt_path
        
    except IOError as e:
        logger.error(f"Failed to save receipt to {receipt_path}: {e}")
        raise


def verify_session_receipt(receipt: dict, peer_cert_pem: str) -> bool:
    """
    Verify a session receipt's signature using peer's certificate.
    
    Args:
        receipt: Receipt dict with fields: transcript_sha256, sig, etc.
        peer_cert_pem: PEM-encoded peer certificate for verification
        
    Returns:
        True if signature valid, False otherwise
        
    Raises:
        ValueError: If receipt fields missing
        Exception: If verification fails
    """
    import base64
    
    from app.crypto.rsa_signer import verify_signature_with_pem
    
    # Validate receipt structure
    required_fields = ["transcript_sha256", "sig"]
    if not all(f in receipt for f in required_fields):
        raise ValueError(f"Invalid receipt: missing required fields. Has: {list(receipt.keys())}")
    
    transcript_hash = receipt["transcript_sha256"]
    signature_b64 = receipt["sig"]
    
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception as e:
        logger.error(f"Failed to decode receipt signature: {e}")
        return False
    
    try:
        # Verify signature over transcript hash
        is_valid = verify_signature_with_pem(
            transcript_hash.encode('utf-8'),
            signature_bytes,
            peer_cert_pem
        )
        return is_valid
        
    except Exception as e:
        logger.error(f"Receipt verification failed: {e}")
        return False
