#!/usr/bin/env python3
"""
Offline verification of SecureChat session transcripts and receipts.

Verifies message signatures and session receipts for non-repudiation.

Usage:
    python scripts/verify_session.py transcripts/alice_session_XXX.log \\
        transcripts/alice_receipt_XXX.json certs/server_cert.pem
"""

import argparse
import json
import logging
import sys
import hashlib
import base64
from pathlib import Path
from typing import Tuple, Dict, List, Optional, Any

# Add parent directory to path for app module imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def verify_message_signature(line: str, peer_cert_pem: str) -> Tuple[bool, Optional[str]]:
    """
    Verify single transcript message signature.
    
    Parses line (direction|seqno|ts|ct_b64|sig_b64|peer_fp), reconstructs digest, verifies RSA-PSS.
    
    Returns: (is_valid, error_msg or None)
    """
    try:
        # Parse transcript line
        parts = line.strip().split('|')
        if len(parts) != 6:
            return False, f"Invalid line format: expected 6 fields, got {len(parts)}"
        
        direction, seqno_str, ts_str, ct_b64, sig_b64, peer_fp = parts
        
        # Validate fields
        if direction not in ("SENT", "RECV"):
            return False, f"Invalid direction: {direction}"
        
        try:
            seqno = int(seqno_str)
            ts = int(ts_str)
        except ValueError as e:
            return False, f"Invalid seqno/ts: {e}"
        
        # Decode ciphertext from base64
        try:
            ciphertext_bytes = base64.b64decode(ct_b64)
        except Exception as e:
            return False, f"Invalid base64 ciphertext: {e}"
        
        # Reconstruct digest: SHA256(seqno_bytes(4) || ts_bytes(8) || ciphertext)
        # This matches the format in app/client/client.py and app/server/server.py
        digest_input = (
            seqno.to_bytes(4, byteorder='big') +
            ts.to_bytes(8, byteorder='big') +
            ciphertext_bytes
        )
        digest = hashlib.sha256(digest_input).digest()
        
        # Decode signature
        try:
            signature_bytes = base64.b64decode(sig_b64)
        except Exception as e:
            return False, f"Invalid base64 signature: {e}"
        
        # Verify signature using peer certificate
        try:
            from app.crypto.rsa_signer import verify_signature
            from app.crypto.cert_validator import load_certificate_from_pem_string
            
            cert = load_certificate_from_pem_string(peer_cert_pem)
            is_valid = verify_signature(digest, signature_bytes, cert)
            
            if is_valid:
                return True, ""
            else:
                return False, "RSA-PSS signature verification failed"
                
        except Exception as e:
            return False, f"Verification error: {e}"
    
    except Exception as e:
        return False, f"Unexpected error: {e}"


def verify_transcript_receipt(transcript_path: str, receipt_path: str, 
                              peer_cert_pem: str) -> Dict[str, Any]:
    """
    Verify transcript integrity and receipt signature.
    
    Steps: Read transcript, compute SHA256, verify receipt signature.
    
    Returns: Dict with 'valid', 'details', 'error'
    """
    details = {
        "transcript_hash": "",
        "receipt_hash": "",
        "hash_match": False,
        "receipt_sig_valid": False,
        "first_seq": 0,
        "last_seq": 0,
        "error": ""
    }
    
    try:
        # Read transcript
        transcript_file = Path(transcript_path)
        if not transcript_file.exists():
            details["error"] = f"Transcript file not found: {transcript_path}"
            return False, details
        
        with open(transcript_file, 'r') as f:
            transcript_lines = f.readlines()
        
        if not transcript_lines:
            details["error"] = "Transcript is empty"
            return False, details
        
        # Compute transcript hash (SHA256 of concatenated lines)
        transcript_data = ''.join(transcript_lines)
        transcript_hash = hashlib.sha256(transcript_data.encode('utf-8')).hexdigest()
        details["transcript_hash"] = transcript_hash
        
        # Extract sequence numbers
        seqnos = []
        for line in transcript_lines:
            parts = line.strip().split('|')
            if len(parts) >= 2:
                try:
                    seqno = int(parts[1])
                    seqnos.append(seqno)
                except ValueError:
                    pass
        
        if seqnos:
            details["first_seq"] = min(seqnos)
            details["last_seq"] = max(seqnos)
        
        # Read receipt
        receipt_file = Path(receipt_path)
        if not receipt_file.exists():
            details["error"] = f"Receipt file not found: {receipt_path}"
            return False, details
        
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
        
        # Check receipt structure
        if "transcript_sha256" not in receipt:
            details["error"] = "Receipt missing 'transcript_sha256' field"
            return False, details
        
        if "sig" not in receipt:
            details["error"] = "Receipt missing 'sig' field"
            return False, details
        
        receipt_hash = receipt["transcript_sha256"]
        details["receipt_hash"] = receipt_hash
        
        # Check hash match
        hash_match = transcript_hash == receipt_hash
        details["hash_match"] = hash_match
        
        if not hash_match:
            details["error"] = (
                f"Transcript hash mismatch!\n"
                f"  Computed: {transcript_hash}\n"
                f"  Receipt:  {receipt_hash}"
            )
            return False, details
        
        # Verify receipt signature
        try:
            from app.crypto.rsa_signer import verify_signature
            from app.crypto.cert_validator import load_certificate_from_pem_string
            
            # Signature is over the transcript hash (as bytes)
            digest = transcript_hash.encode('utf-8')
            
            try:
                signature_bytes = base64.b64decode(receipt["sig"])
            except Exception as e:
                details["error"] = f"Invalid receipt signature encoding: {e}"
                return False, details
            
            cert = load_certificate_from_pem_string(peer_cert_pem)
            is_valid = verify_signature(digest, signature_bytes, cert)
            
            details["receipt_sig_valid"] = is_valid
            
            if not is_valid:
                details["error"] = "Receipt signature verification failed"
                return False, details
            
        except Exception as e:
            details["error"] = f"Receipt verification error: {e}"
            return False, details
        
        # All checks passed
        return True, details
        
    except json.JSONDecodeError as e:
        details["error"] = f"Invalid JSON in receipt: {e}"
        return False, details
    except Exception as e:
        details["error"] = f"Unexpected error: {e}"
        return False, details


def verify_all_messages(transcript_path: str, peer_cert_pem: str) -> Dict:
    """
    Verify all message signatures in a transcript.
    
    Args:
        transcript_path: Path to .log transcript file
        peer_cert_pem: PEM-encoded certificate for verification
        
    Returns:
        {
            "total": int,
            "valid": int,
            "invalid": int,
            "results": [
                {"line": str, "seqno": int, "valid": bool, "error": str},
                ...
            ]
        }
    """
    results = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "results": []
    }
    
    try:
        transcript_file = Path(transcript_path)
        if not transcript_file.exists():
            logger.error(f"Transcript not found: {transcript_path}")
            return results
        
        with open(transcript_file, 'r') as f:
            lines = f.readlines()
        
        results["total"] = len(lines)
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Extract seqno for reporting
            parts = line.split('|')
            seqno = int(parts[1]) if len(parts) >= 2 else line_num
            
            # Verify signature
            is_valid, error = verify_message_signature(line, peer_cert_pem)
            
            if is_valid:
                results["valid"] += 1
            else:
                results["invalid"] += 1
            
            results["results"].append({
                "line": line_num,
                "seqno": seqno,
                "valid": is_valid,
                "error": error
            })
        
        return results
        
    except Exception as e:
        logger.error(f"Error verifying messages: {e}")
        return results


def print_results(args):
    """
    Main verification function - verifies messages and receipt, prints results.
    
    Args:
        args: Parsed command-line arguments
    """
    # Validate arguments
    if not args.transcript:
        logger.error("--transcript required")
        return 2
    
    if not args.receipt:
        logger.error("--receipt required")
        return 2
    
    if not args.cert:
        logger.error("--cert required")
        return 2
    
    # Check file existence
    transcript_file = Path(args.transcript)
    receipt_file = Path(args.receipt)
    cert_file = Path(args.cert)
    
    for path, name in [(transcript_file, "Transcript"), (receipt_file, "Receipt"), (cert_file, "Certificate")]:
        if not path.exists():
            logger.error(f"{name} not found: {path}")
            return 2
    
    # Load certificate
    try:
        with open(cert_file, 'r') as f:
            peer_cert_pem = f.read()
    except Exception as e:
        logger.error(f"Failed to load certificate: {e}")
        return 2
    
    logger.info(f"Loading transcript: {transcript_file}")
    logger.info(f"Loading receipt: {receipt_file}")
    logger.info(f"Using certificate: {cert_file}")
    print()
    
    # Verify all messages
    print("=" * 70)
    print("MESSAGE SIGNATURE VERIFICATION")
    print("=" * 70)
    
    msg_results = verify_all_messages(str(transcript_file), peer_cert_pem)
    
    print(f"Total messages: {msg_results['total']}")
    print(f"Valid signatures: {msg_results['valid']}")
    print(f"Invalid signatures: {msg_results['invalid']}")
    
    if msg_results['invalid'] > 0:
        print("\nInvalid messages:")
        for result in msg_results['results']:
            if not result['valid']:
                print(f"  Line {result['line']} (seqno={result['seqno']}): {result['error']}")
    else:
        print("\n✓ All message signatures valid")
    
    print()
    
    # Verify transcript receipt
    print("=" * 70)
    print("TRANSCRIPT & RECEIPT VERIFICATION")
    print("=" * 70)
    
    receipt_valid, receipt_details = verify_transcript_receipt(
        str(transcript_file),
        str(receipt_file),
        peer_cert_pem
    )
    
    print(f"Sequence range: {receipt_details['first_seq']}-{receipt_details['last_seq']}")
    print(f"Computed hash:  {receipt_details['transcript_hash']}")
    print(f"Receipt hash:   {receipt_details['receipt_hash']}")
    print(f"Hashes match:   {'✓ Yes' if receipt_details['hash_match'] else '✗ No'}")
    print(f"Receipt signature: {'✓ Valid' if receipt_details['receipt_sig_valid'] else '✗ Invalid'}")
    
    if receipt_details['error']:
        print(f"\nError: {receipt_details['error']}")
    
    print()
    
    # Final verdict
    print("=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    
    all_valid = (msg_results['invalid'] == 0) and receipt_valid
    
    if all_valid:
        print("\n✓ ALL VERIFICATIONS PASSED")
        print("  - All message signatures verified")
        print("  - Transcript hash matches receipt")
        print("  - Receipt signature valid")
        print("\nNon-repudiation guarantees satisfied!")
        return 0
    else:
        print("\n✗ VERIFICATION FAILED")
        if msg_results['invalid'] > 0:
            print(f"  - {msg_results['invalid']} invalid message signature(s)")
        if not receipt_valid:
            print(f"  - Receipt verification failed")
        print("\nPossible tampering detected!")
        return 1


def main():
    """Parse arguments and run verification."""
    parser = argparse.ArgumentParser(
        description='Offline verification of SecureChat session transcripts and receipts',
        epilog='''
Examples:
  # Verify a complete session
  python scripts/verify_session.py \\
    --transcript transcripts/alice_session_1762699111434.log \\
    --receipt transcripts/alice_receipt_1762699111434.json \\
    --cert certs/server_cert.pem

  # Tamper test (modify transcript and verify fails)
  sed -i '' 's/SENT/TAMPERED/' transcripts/alice_session_*.log
  python scripts/verify_session.py --transcript ... --receipt ... --cert ...
        '''
    )
    
    parser.add_argument(
        '--transcript',
        type=str,
        help='Path to session transcript (.log file)'
    )
    
    parser.add_argument(
        '--receipt',
        type=str,
        help='Path to session receipt (.json file)'
    )
    
    parser.add_argument(
        '--cert',
        type=str,
        help='Path to peer certificate (PEM file) for verification'
    )
    
    args = parser.parse_args()
    
    exit_code = print_results(args)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
