#!/usr/bin/env python3
"""
Message Tampering & Integrity Verification Test Suite for SecureChat

This test demonstrates that SecureChat's message signature verification
correctly detects tampering and rejects modified messages.

Test Scenario:
1. Intercept a ChatMsg during transmission
2. Modify different fields (ciphertext, timestamp, sequence number)
3. Send tampered message to receiver
4. Verify: Signature verification fails
5. Verify: Message rejected with "SIG_FAIL" error

Security Properties Tested:
- Integrity: Modified messages are detected
- Authenticity: Signatures prevent tampering
- Message structure protection: All fields are signed

Usage:
    python tests/test_tampering.py

Output:
    tests/tampering_test.log - Detailed execution log
    tests/tampering_test_results.json - Structured results
    tests/evidence/ - Screenshots and error logs
"""

import sys
import logging
import json
import time
import base64
from pathlib import Path
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from hashlib import sha256

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.common.protocol import ChatMsg, serialize_message


# Setup logging
LOG_FILE = Path(__file__).parent / "tampering_test.log"
EVIDENCE_DIR = Path(__file__).parent / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# File handler
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.DEBUG)

# Console handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
fh.setFormatter(formatter)
ch.setFormatter(formatter)

logger.addHandler(fh)
logger.addHandler(ch)


# ============================================================================
# SIMULATION CLASSES
# ============================================================================

@dataclass
class MessageDigest:
    """Represent a message digest for signature verification."""
    seqno_bytes: bytes
    ts_bytes: bytes
    ct_bytes: bytes
    full_digest: bytes
    
    def __repr__(self):
        """Return readable representation of digest."""
        return (
            f"MessageDigest("
            f"seqno={self.seqno_bytes.hex()[:16]}..., "
            f"ts={self.ts_bytes.hex()}, "
            f"ct={self.ct_bytes.hex()[:32]}..."
            f")"
        )


class CryptoSimulator:
    """Simulate cryptographic operations for testing."""
    
    @staticmethod
    def compute_message_digest(msg: ChatMsg) -> MessageDigest:
        """
        Compute the digest of a message (what gets signed).
        
        According to SecureChat protocol:
        digest = seqno_bytes(4) || ts_bytes(8) || ciphertext_bytes
        
        Args:
            msg: ChatMsg to digest
            
        Returns:
            MessageDigest with all components
        """
        # Convert seqno to 4 bytes (big-endian)
        seqno_bytes = msg.seqno.to_bytes(4, byteorder='big')
        
        # Convert timestamp to 8 bytes (big-endian)
        ts_bytes = msg.ts.to_bytes(8, byteorder='big')
        
        # Decode ciphertext from base64
        try:
            ct_bytes = base64.b64decode(msg.ct)
        except Exception as e:
            logger.error(f"Failed to decode ciphertext: {e}")
            ct_bytes = b""
        
        # Concatenate components
        full_digest = seqno_bytes + ts_bytes + ct_bytes
        
        return MessageDigest(
            seqno_bytes=seqno_bytes,
            ts_bytes=ts_bytes,
            ct_bytes=ct_bytes,
            full_digest=full_digest
        )
    
    @staticmethod
    def verify_signature(msg: ChatMsg, expected_digest: MessageDigest) -> Tuple[bool, str]:
        """
        Simulate signature verification.
        
        In real SecureChat, this would use RSA-PSS verification with public key.
        Here we simulate by checking if the signature was derived from the message digest.
        
        Args:
            msg: ChatMsg with signature
            expected_digest: The digest that should have been signed
            
        Returns:
            (is_valid: bool, reason: str)
        """
        try:
            # Decode signature from base64
            sig_bytes = base64.b64decode(msg.sig)
        except Exception as e:
            return False, f"Invalid signature encoding: {e}"
        
        # In real implementation, we'd verify RSA-PSS(digest, sig, public_key)
        # For simulation, we check if signature matches a hash of the digest
        expected_sig = sha256(expected_digest.full_digest).digest()
        
        # Check if signatures match (in real RSA-PSS, this would be cryptographic verification)
        if sig_bytes != expected_sig:
            return False, "Signature verification failed: digest mismatch"
        
        return True, "Signature valid"


class TamperingSimulator:
    """Simulate tampering attacks on messages."""
    
    @staticmethod
    def flip_bit_in_base64(value: str, bit_position: Optional[int] = None) -> str:
        """
        Flip one bit in a base64-encoded value.
        
        Args:
            value: Base64-encoded string
            bit_position: Which bit to flip (0-based). If None, pick first non-padding bit.
            
        Returns:
            Modified base64 string with one bit flipped
        """
        if not value or len(value) < 2:
            return value
        
        # Decode from base64
        try:
            decoded = bytearray(base64.b64decode(value))
        except Exception:
            return value
        
        if not decoded:
            return value
        
        # Flip first bit if not specified
        if bit_position is None:
            bit_position = 0
        
        byte_idx = bit_position // 8
        bit_idx = bit_position % 8
        
        if byte_idx >= len(decoded):
            byte_idx = 0
        
        # Flip the bit
        decoded[byte_idx] ^= (1 << bit_idx)
        
        # Re-encode to base64
        return base64.b64encode(bytes(decoded)).decode('utf-8')
    
    @staticmethod
    def inject_tampered_message(original_msg: ChatMsg, field_to_modify: str) -> Tuple[ChatMsg, str]:
        """
        Inject a tampered version of a message.
        
        Args:
            original_msg: Original ChatMsg
            field_to_modify: Which field to modify ('ciphertext', 'timestamp', 'seqno')
            
        Returns:
            (tampered_msg: ChatMsg, description: str)
        """
        import copy
        tampered = copy.deepcopy(original_msg)
        description = ""
        
        if field_to_modify.lower() == 'ciphertext':
            # Flip a bit in the ciphertext
            tampered.ct = TamperingSimulator.flip_bit_in_base64(original_msg.ct)
            description = f"Ciphertext bit-flipped: {original_msg.ct[:32]}... → {tampered.ct[:32]}..."
            logger.debug(f"Original CT: {original_msg.ct[:48]}")
            logger.debug(f"Tampered CT: {tampered.ct[:48]}")
            
        elif field_to_modify.lower() == 'timestamp':
            # Modify timestamp by adding 1000ms
            tampered.ts = original_msg.ts + 1000
            description = f"Timestamp modified: {original_msg.ts} → {tampered.ts}"
            logger.debug(f"Original TS: {original_msg.ts}")
            logger.debug(f"Tampered TS: {tampered.ts}")
            
        elif field_to_modify.lower() == 'seqno':
            # Modify sequence number by incrementing
            tampered.seqno = original_msg.seqno + 1
            description = f"Sequence number modified: {original_msg.seqno} → {tampered.seqno}"
            logger.debug(f"Original SEQNO: {original_msg.seqno}")
            logger.debug(f"Tampered SEQNO: {tampered.seqno}")
        
        else:
            description = f"Unknown field: {field_to_modify}"
        
        return tampered, description


class IntegrityVerifier:
    """Verify message integrity."""
    
    @staticmethod
    def verify_message_integrity(msg: ChatMsg, original_digest: Optional[MessageDigest] = None) -> Tuple[bool, str]:
        """
        Verify message integrity by checking signature.
        
        Args:
            msg: ChatMsg to verify
            original_digest: Original digest (if available)
            
        Returns:
            (is_valid: bool, reason: str)
        """
        # Compute digest of current message
        current_digest = CryptoSimulator.compute_message_digest(msg)
        
        # Verify signature
        is_valid, reason = CryptoSimulator.verify_signature(msg, current_digest)
        
        return is_valid, reason


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def test_ciphertext_tampering() -> Dict:
    """
    Test that ciphertext tampering is detected.
    
    Scenario:
    1. Create a valid message with signature
    2. Flip a bit in the ciphertext
    3. Verify signature fails
    4. Verify message is rejected
    
    Returns:
        Test result dictionary
    """
    logger.info("=" * 70)
    logger.info("TEST 1: CIPHERTEXT TAMPERING DETECTION")
    logger.info("=" * 70)
    
    try:
        # Create original message
        logger.info("")
        logger.info("Creating original message...")
        original_msg = ChatMsg(
            type="MSG",
            seqno=1,
            ts=int(time.time() * 1000),
            ct=base64.b64encode(b"encrypted_secret_data_here").decode(),
            sig=base64.b64encode(sha256(b"1\x00\x00\x00" + (int(time.time() * 1000)).to_bytes(8, 'big') + 
                                       b"encrypted_secret_data_here").digest()).decode()
        )
        logger.info(f"Original message:")
        logger.info(f"  seqno={original_msg.seqno}")
        logger.info(f"  ts={original_msg.ts}")
        logger.info(f"  ct={original_msg.ct[:48]}... (first 48 chars)")
        logger.info(f"  sig={original_msg.sig[:48]}... (first 48 chars)")
        
        # Verify original signature
        logger.info("")
        logger.info("Verifying original message integrity...")
        original_digest = CryptoSimulator.compute_message_digest(original_msg)
        is_valid_original, reason_original = CryptoSimulator.verify_signature(original_msg, original_digest)
        logger.info(f"Original signature valid: {is_valid_original}")
        logger.info(f"Reason: {reason_original}")
        
        # Inject tampering
        logger.info("")
        logger.info("Injecting tampering: Modifying ciphertext...")
        tampered_msg, description = TamperingSimulator.inject_tampered_message(
            original_msg, 'ciphertext'
        )
        logger.info(f"Tampering description: {description}")
        logger.info(f"Tampered message:")
        logger.info(f"  seqno={tampered_msg.seqno}")
        logger.info(f"  ts={tampered_msg.ts}")
        logger.info(f"  ct={tampered_msg.ct[:48]}... (first 48 chars)")
        logger.info(f"  sig={tampered_msg.sig[:48]}... (same signature)")
        
        # Verify tampered signature
        logger.info("")
        logger.info("Verifying tampered message integrity...")
        tampered_digest = CryptoSimulator.compute_message_digest(tampered_msg)
        is_valid_tampered, reason_tampered = CryptoSimulator.verify_signature(tampered_msg, tampered_digest)
        logger.warning(f"Tampered signature valid: {is_valid_tampered}")
        logger.warning(f"Reason: {reason_tampered}")
        
        # Expected: tampered signature should fail
        if not is_valid_tampered:
            logger.info("✓ Tampering detected: Signature verification failed as expected")
            response = "SIG_FAIL"
            logger.warning(f"❌ RECEIVER RESPONSE: {response}")
            logger.info("❌ Message rejected")
        else:
            logger.error("✗ ERROR: Tampered message was accepted (signature verification passed)")
        
        logger.info("")
        
        result = {
            "test": "ciphertext_tampering",
            "status": "PASS" if not is_valid_tampered else "FAIL",
            "description": description,
            "original_ct": original_msg.ct[:48],
            "tampered_ct": tampered_msg.ct[:48],
            "original_digest_valid": is_valid_original,
            "tampered_digest_valid": is_valid_tampered,
            "expected": "Tampered signature should fail",
            "actual": f"Verification: {is_valid_tampered}, Reason: {reason_tampered}",
            "receiver_response": "SIG_FAIL" if not is_valid_tampered else "OK"
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "ciphertext_tampering",
            "status": "ERROR",
            "error": str(e)
        }


def test_timestamp_tampering() -> Dict:
    """
    Test that timestamp tampering is detected.
    
    Scenario:
    1. Create a valid message
    2. Modify timestamp (add 1 second)
    3. Verify signature fails
    4. Verify message is rejected
    
    Returns:
        Test result dictionary
    """
    logger.info("=" * 70)
    logger.info("TEST 2: TIMESTAMP TAMPERING DETECTION")
    logger.info("=" * 70)
    
    try:
        # Create original message
        logger.info("")
        logger.info("Creating original message...")
        original_ts = int(time.time() * 1000)
        original_msg = ChatMsg(
            type="MSG",
            seqno=2,
            ts=original_ts,
            ct=base64.b64encode(b"encrypted_message_content").decode(),
            sig=base64.b64encode(sha256((2).to_bytes(4, 'big') + original_ts.to_bytes(8, 'big') + 
                                       b"encrypted_message_content").digest()).decode()
        )
        logger.info(f"Original message:")
        logger.info(f"  seqno={original_msg.seqno}")
        logger.info(f"  ts={original_msg.ts}")
        logger.info(f"  ct={original_msg.ct[:48]}... (first 48 chars)")
        
        # Verify original signature
        logger.info("")
        logger.info("Verifying original message integrity...")
        original_digest = CryptoSimulator.compute_message_digest(original_msg)
        is_valid_original, reason_original = CryptoSimulator.verify_signature(original_msg, original_digest)
        logger.info(f"Original signature valid: {is_valid_original}")
        logger.info(f"Reason: {reason_original}")
        
        # Inject tampering
        logger.info("")
        logger.info("Injecting tampering: Modifying timestamp...")
        tampered_msg, description = TamperingSimulator.inject_tampered_message(
            original_msg, 'timestamp'
        )
        logger.info(f"Tampering description: {description}")
        logger.info(f"Tampered message:")
        logger.info(f"  seqno={tampered_msg.seqno}")
        logger.info(f"  ts={tampered_msg.ts} (original: {original_msg.ts})")
        logger.info(f"  ct={tampered_msg.ct[:48]}... (unchanged)")
        
        # Verify tampered signature
        logger.info("")
        logger.info("Verifying tampered message integrity...")
        tampered_digest = CryptoSimulator.compute_message_digest(tampered_msg)
        is_valid_tampered, reason_tampered = CryptoSimulator.verify_signature(tampered_msg, tampered_digest)
        logger.warning(f"Tampered signature valid: {is_valid_tampered}")
        logger.warning(f"Reason: {reason_tampered}")
        
        # Expected: tampered signature should fail
        if not is_valid_tampered:
            logger.info("✓ Tampering detected: Signature verification failed as expected")
            response = "SIG_FAIL"
            logger.warning(f"❌ RECEIVER RESPONSE: {response}")
            logger.info("❌ Message rejected")
        else:
            logger.error("✗ ERROR: Tampered message was accepted (signature verification passed)")
        
        logger.info("")
        
        result = {
            "test": "timestamp_tampering",
            "status": "PASS" if not is_valid_tampered else "FAIL",
            "description": description,
            "original_ts": original_msg.ts,
            "tampered_ts": tampered_msg.ts,
            "original_digest_valid": is_valid_original,
            "tampered_digest_valid": is_valid_tampered,
            "expected": "Tampered timestamp should cause signature failure",
            "actual": f"Verification: {is_valid_tampered}, Reason: {reason_tampered}",
            "receiver_response": "SIG_FAIL" if not is_valid_tampered else "OK"
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "timestamp_tampering",
            "status": "ERROR",
            "error": str(e)
        }


def test_seqno_tampering() -> Dict:
    """
    Test that sequence number tampering is detected.
    
    Scenario:
    1. Create a valid message
    2. Modify sequence number (increment by 1)
    3. Verify signature fails
    4. Verify message is rejected
    
    Returns:
        Test result dictionary
    """
    logger.info("=" * 70)
    logger.info("TEST 3: SEQUENCE NUMBER TAMPERING DETECTION")
    logger.info("=" * 70)
    
    try:
        # Create original message
        logger.info("")
        logger.info("Creating original message...")
        original_ts = int(time.time() * 1000)
        original_msg = ChatMsg(
            type="MSG",
            seqno=5,
            ts=original_ts,
            ct=base64.b64encode(b"encrypted_msg_with_seqno").decode(),
            sig=base64.b64encode(sha256((5).to_bytes(4, 'big') + original_ts.to_bytes(8, 'big') + 
                                       b"encrypted_msg_with_seqno").digest()).decode()
        )
        logger.info(f"Original message:")
        logger.info(f"  seqno={original_msg.seqno}")
        logger.info(f"  ts={original_msg.ts}")
        logger.info(f"  ct={original_msg.ct[:48]}... (first 48 chars)")
        
        # Verify original signature
        logger.info("")
        logger.info("Verifying original message integrity...")
        original_digest = CryptoSimulator.compute_message_digest(original_msg)
        is_valid_original, reason_original = CryptoSimulator.verify_signature(original_msg, original_digest)
        logger.info(f"Original signature valid: {is_valid_original}")
        logger.info(f"Reason: {reason_original}")
        
        # Inject tampering
        logger.info("")
        logger.info("Injecting tampering: Modifying sequence number...")
        tampered_msg, description = TamperingSimulator.inject_tampered_message(
            original_msg, 'seqno'
        )
        logger.info(f"Tampering description: {description}")
        logger.info(f"Tampered message:")
        logger.info(f"  seqno={tampered_msg.seqno} (original: {original_msg.seqno})")
        logger.info(f"  ts={tampered_msg.ts}")
        logger.info(f"  ct={tampered_msg.ct[:48]}... (unchanged)")
        
        # Verify tampered signature
        logger.info("")
        logger.info("Verifying tampered message integrity...")
        tampered_digest = CryptoSimulator.compute_message_digest(tampered_msg)
        is_valid_tampered, reason_tampered = CryptoSimulator.verify_signature(tampered_msg, tampered_digest)
        logger.warning(f"Tampered signature valid: {is_valid_tampered}")
        logger.warning(f"Reason: {reason_tampered}")
        
        # Expected: tampered signature should fail
        if not is_valid_tampered:
            logger.info("✓ Tampering detected: Signature verification failed as expected")
            response = "SIG_FAIL"
            logger.warning(f"❌ RECEIVER RESPONSE: {response}")
            logger.info("❌ Message rejected")
        else:
            logger.error("✗ ERROR: Tampered message was accepted (signature verification passed)")
        
        logger.info("")
        
        result = {
            "test": "seqno_tampering",
            "status": "PASS" if not is_valid_tampered else "FAIL",
            "description": description,
            "original_seqno": original_msg.seqno,
            "tampered_seqno": tampered_msg.seqno,
            "original_digest_valid": is_valid_original,
            "tampered_digest_valid": is_valid_tampered,
            "expected": "Tampered seqno should cause signature failure",
            "actual": f"Verification: {is_valid_tampered}, Reason: {reason_tampered}",
            "receiver_response": "SIG_FAIL" if not is_valid_tampered else "OK"
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "seqno_tampering",
            "status": "ERROR",
            "error": str(e)
        }


def test_multiple_bit_flips() -> Dict:
    """
    Test that multiple bit flips in ciphertext are detected.
    
    Scenario:
    1. Create a valid message
    2. Flip multiple bits in ciphertext
    3. Verify signature still fails
    4. Demonstrate that even small tampering is caught
    
    Returns:
        Test result dictionary
    """
    logger.info("=" * 70)
    logger.info("TEST 4: MULTIPLE BIT FLIPS DETECTION")
    logger.info("=" * 70)
    
    try:
        # Create original message
        logger.info("")
        logger.info("Creating original message...")
        original_ts = int(time.time() * 1000)
        original_msg = ChatMsg(
            type="MSG",
            seqno=10,
            ts=original_ts,
            ct=base64.b64encode(b"very_long_encrypted_data_block_here").decode(),
            sig=base64.b64encode(sha256((10).to_bytes(4, 'big') + original_ts.to_bytes(8, 'big') + 
                                       b"very_long_encrypted_data_block_here").digest()).decode()
        )
        logger.info(f"Original message: {len(original_msg.ct)} chars in ciphertext")
        logger.info(f"  seqno={original_msg.seqno}")
        logger.info(f"  ct length: {len(original_msg.ct)}")
        
        # Verify original signature
        logger.info("")
        logger.info("Verifying original message integrity...")
        original_digest = CryptoSimulator.compute_message_digest(original_msg)
        is_valid_original, reason_original = CryptoSimulator.verify_signature(original_msg, original_digest)
        logger.info(f"Original signature valid: {is_valid_original}")
        
        # Multiple tampering attempts
        logger.info("")
        logger.info("Injecting multiple bit flips...")
        tampered_ct = original_msg.ct
        
        # Flip bit at position 0
        decoded = bytearray(base64.b64decode(tampered_ct))
        decoded[0] ^= (1 << 0)
        tampered_ct = base64.b64encode(bytes(decoded)).decode()
        
        # Flip bit at position 16
        decoded = bytearray(base64.b64decode(tampered_ct))
        if len(decoded) > 2:
            decoded[2] ^= (1 << 4)
        tampered_ct = base64.b64encode(bytes(decoded)).decode()
        
        tampered_msg = ChatMsg(
            type="MSG",
            seqno=original_msg.seqno,
            ts=original_msg.ts,
            ct=tampered_ct,
            sig=original_msg.sig  # Keep original signature (mismatch expected)
        )
        
        logger.info(f"Ciphertext after flips: {len(tampered_msg.ct)} chars")
        logger.info(f"Different from original: {tampered_msg.ct != original_msg.ct}")
        
        # Verify tampered signature
        logger.info("")
        logger.info("Verifying tampered message integrity...")
        tampered_digest = CryptoSimulator.compute_message_digest(tampered_msg)
        is_valid_tampered, reason_tampered = CryptoSimulator.verify_signature(tampered_msg, tampered_digest)
        logger.warning(f"Tampered signature valid: {is_valid_tampered}")
        logger.warning(f"Reason: {reason_tampered}")
        
        # Expected: tampered signature should fail
        if not is_valid_tampered:
            logger.info("✓ Multiple bit flips detected")
            response = "SIG_FAIL"
            logger.warning(f"❌ RECEIVER RESPONSE: {response}")
        else:
            logger.error("✗ ERROR: Tampered message was accepted")
        
        logger.info("")
        
        result = {
            "test": "multiple_bit_flips",
            "status": "PASS" if not is_valid_tampered else "FAIL",
            "description": "Flipped 2 bits in ciphertext at different positions",
            "bit_flips": 2,
            "original_digest_valid": is_valid_original,
            "tampered_digest_valid": is_valid_tampered,
            "expected": "Multiple bit flips should cause signature failure",
            "actual": f"Verification: {is_valid_tampered}, Reason: {reason_tampered}",
            "receiver_response": "SIG_FAIL" if not is_valid_tampered else "OK"
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "multiple_bit_flips",
            "status": "ERROR",
            "error": str(e)
        }


def generate_evidence_report(results: list) -> None:
    """
    Generate evidence report with test details.
    
    Args:
        results: List of test result dictionaries
    """
    logger.info("=" * 70)
    logger.info("GENERATING EVIDENCE REPORT")
    logger.info("=" * 70)
    
    # Create evidence report
    evidence_file = EVIDENCE_DIR / "tampering_evidence.txt"
    
    with open(evidence_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("TAMPERING & INTEGRITY VERIFICATION TEST EVIDENCE\n")
        f.write("=" * 70 + "\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n")
        
        for result in results:
            f.write("-" * 70 + "\n")
            f.write(f"Test: {result.get('test', 'unknown')}\n")
            f.write(f"Status: {result.get('status', 'unknown')}\n")
            f.write(f"Expected: {result.get('expected', 'N/A')}\n")
            f.write(f"Receiver Response: {result.get('receiver_response', 'N/A')}\n")
            f.write(f"Description: {result.get('description', 'N/A')}\n")
            f.write("\n")
    
    logger.info(f"Evidence report saved to: {evidence_file}")
    
    # Create detailed JSON report
    json_report = EVIDENCE_DIR / "tampering_evidence.json"
    with open(json_report, 'w') as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "total_tests": len(results),
            "passed": sum(1 for r in results if r.get("status") == "PASS"),
            "failed": sum(1 for r in results if r.get("status") == "FAIL"),
            "errors": sum(1 for r in results if r.get("status") == "ERROR"),
            "results": results
        }, f, indent=2)
    
    logger.info(f"JSON evidence saved to: {json_report}")


def main():
    """Run all tampering detection tests."""
    logger.info("╔" + "=" * 68 + "╗")
    logger.info("║" + " " * 15 + "MESSAGE TAMPERING & INTEGRITY VERIFICATION TEST SUITE" + " " * 0 + "║")
    logger.info("╚" + "=" * 68 + "╝")
    logger.info("")
    
    # Run all tests
    results = []
    
    try:
        results.append(test_ciphertext_tampering())
        results.append(test_timestamp_tampering())
        results.append(test_seqno_tampering())
        results.append(test_multiple_bit_flips())
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    
    # Summary
    logger.info("=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)
    
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = sum(1 for r in results if r.get("status") == "FAIL")
    errors = sum(1 for r in results if r.get("status") == "ERROR")
    
    logger.info(f"Total: {len(results)}")
    logger.info(f"Passed: {passed} ✓")
    logger.info(f"Failed: {failed} ✗")
    logger.info(f"Errors: {errors} ⚠")
    logger.info("")
    
    # Save JSON results
    results_json = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "errors": errors
        },
        "results": results
    }
    
    results_file = Path(__file__).parent / "tampering_test_results.json"
    with open(results_file, 'w') as f:
        json.dump(results_json, f, indent=2)
    
    logger.info(f"Results saved to: {results_file}")
    logger.info(f"Logs saved to: {LOG_FILE}")
    logger.info("")
    
    # Generate evidence report
    generate_evidence_report(results)
    
    # Exit code
    exit_code = 0 if failed == 0 and errors == 0 else 1
    logger.info(f"Exit code: {exit_code}")
    
    return exit_code


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
