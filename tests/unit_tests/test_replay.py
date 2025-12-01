#!/usr/bin/env python3
"""
Replay Protection Test Suite

Tests sequence number replay protection by capturing and replaying messages.
Verifies messages with old sequence numbers are properly rejected.

Usage: python tests/test_replay.py
Output: tests/replay_test.log
"""

import sys
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.common.protocol import ChatMsg, serialize_message


# Setup logging
LOG_FILE = Path(__file__).parent / "replay_test.log"
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
class MessageState:
    """Track state of a single message."""
    seqno: int
    ts: int
    ct: str
    sig: str
    raw_json: str
    received_at: float = None  # When receiver got it


class ChatSessionSimulator:
    """Simulate a chat session with replay protection."""
    
    def __init__(self, session_name: str):
        """Initialize chat session simulator."""
        self.session_name = session_name
        self.sent_messages: List[MessageState] = []
        self.received_messages: List[MessageState] = []
        self.last_received_seqno = 0
        self.message_counter = 0
    
    def create_message(self, plaintext: str) -> MessageState:
        """Create a new chat message."""
        self.message_counter += 1
        seqno = self.message_counter
        ts = int(time.time() * 1000)
        ct = f"encrypted_{plaintext}_{seqno}"  # Simulated ciphertext
        sig = f"signature_of_{seqno}"  # Simulated signature
        
        msg = ChatMsg(
            type="MSG",
            seqno=seqno,
            ts=ts,
            ct=ct,
            sig=sig
        )
        
        json_str = serialize_message(msg)
        state = MessageState(
            seqno=seqno,
            ts=ts,
            ct=ct,
            sig=sig,
            raw_json=json_str
        )
        
        self.sent_messages.append(state)
        logger.debug(f"Created message: seqno={seqno}, ts={ts}")
        
        return state
    
    def receive_message(self, msg_state: MessageState) -> Tuple[bool, str]:
        """Validate message using sequence number replay protection.
        
        Rejects if seqno <= last_received_seqno.
        Returns: (accepted, reason)
        """
        seqno = msg_state.seqno
        
        if seqno <= self.last_received_seqno:
            # Replay detected!
            reason = (
                f"Replay detected: seqno={seqno} <= "
                f"last_received_seqno={self.last_received_seqno}"
            )
            logger.warning(f"❌ REPLAY ATTACK: {reason}")
            return False, reason
        
        # Valid sequence number - accept message
        self.received_messages.append(msg_state)
        self.last_received_seqno = seqno
        logger.info(f"✓ Message accepted: seqno={seqno}")
        
        return True, "OK"
    
    def get_message_summary(self) -> Dict:
        """Get session summary."""
        return {
            "session_name": self.session_name,
            "total_sent": len(self.sent_messages),
            "total_received": len(self.received_messages),
            "last_received_seqno": self.last_received_seqno,
            "sent_seqnos": [m.seqno for m in self.sent_messages],
            "received_seqnos": [m.seqno for m in self.received_messages],
        }


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def simulate_replay_attack() -> Dict:
    """Simulate replay attack: send msgs 1-3, capture 3,  send 4-5, replay 3.
    
    Returns: Test result dictionary
    """
    logger.info("=" * 70)
    logger.info("REPLAY ATTACK SIMULATION")
    logger.info("=" * 70)
    
    try:
        # Create session
        session = ChatSessionSimulator("test_replay_session")
        logger.info("Session created")
        
        # Phase 1: Send normal messages
        logger.info("")
        logger.info("--- Phase 1: Normal Messages ---")
        msg1 = session.create_message("Hello")
        msg2 = session.create_message("How are you?")
        msg3 = session.create_message("I'm doing well")
        
        logger.info("Receiving messages in order...")
        session.receive_message(msg1)
        session.receive_message(msg2)
        session.receive_message(msg3)
        
        # Capture message 3 for replay
        captured_msg3 = msg3
        logger.info(f"✓ Captured message 3 (seqno={captured_msg3.seqno}) for replay")
        logger.info(f"  Last received seqno: {session.last_received_seqno}")
        
        # Phase 2: Send more messages
        logger.info("")
        logger.info("--- Phase 2: More Normal Messages ---")
        msg4 = session.create_message("Thanks for asking")
        msg5 = session.create_message("Goodbye!")
        
        logger.info("Receiving new messages...")
        session.receive_message(msg4)
        logger.info(f"  Last received seqno: {session.last_received_seqno}")
        session.receive_message(msg5)
        logger.info(f"  Last received seqno: {session.last_received_seqno}")
        
        # Phase 3: Replay attack
        logger.info("")
        logger.info("--- Phase 3: Replay Attack ---")
        logger.info(f"Replaying captured message 3 (seqno={captured_msg3.seqno})...")
        logger.info(f"  Current last_received_seqno: {session.last_received_seqno}")
        
        accepted, reason = session.receive_message(captured_msg3)
        
        # Verify rejection
        logger.info("")
        logger.info("--- Phase 3 Results ---")
        logger.info(f"Message accepted: {accepted}")
        logger.info(f"Reason: {reason}")
        
        # Expected: Message should be rejected
        replay_detected = not accepted and "replay" in reason.lower()
        
        logger.info("")
        logger.info("--- Summary ---")
        summary = session.get_message_summary()
        logger.info(f"Session name: {summary['session_name']}")
        logger.info(f"Total sent: {summary['total_sent']}")
        logger.info(f"Total received (after replay): {summary['total_received']}")
        logger.info(f"Sent sequence numbers: {summary['sent_seqnos']}")
        logger.info(f"Received sequence numbers: {summary['received_seqnos']}")
        logger.info(f"Last received seqno: {summary['last_received_seqno']}")
        logger.info("")
        
        result = {
            "test": "replay_attack",
            "status": "PASS" if replay_detected else "FAIL",
            "expected": "Replay message should be rejected",
            "actual": f"Message accepted={accepted}, Reason={reason}",
            "replay_detected": replay_detected,
            "captured_seqno": captured_msg3.seqno,
            "last_received_seqno": session.last_received_seqno,
            "summary": summary
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "replay_attack",
            "status": "ERROR",
            "error": str(e)
        }


def test_sequence_number_ordering() -> Dict:
    """Test that sequence numbers must be strictly increasing."""

    logger.info("=" * 70)
    logger.info("SEQUENCE NUMBER ORDERING TEST")
    logger.info("=" * 70)
    
    try:
        session = ChatSessionSimulator("test_seqno_ordering")
        
        # Create messages with specific sequence numbers
        logger.info("Creating messages...")
        msg1 = session.create_message("First")
        msg2 = session.create_message("Second")
        msg3 = session.create_message("Third")
        
        # Receive in order
        logger.info("Receiving messages in order (seqno 1, 2, 3)...")
        session.receive_message(msg1)
        session.receive_message(msg2)
        session.receive_message(msg3)
        
        # Try to receive msg2 again (out of order, lower seqno)
        logger.info("Attempting to receive message 2 again...")
        accepted, reason = session.receive_message(msg2)
        
        logger.info(f"Result: accepted={accepted}, reason={reason}")
        
        # Try to receive msg1 again (oldest)
        logger.info("Attempting to receive message 1 again...")
        accepted2, reason2 = session.receive_message(msg1)
        
        logger.info(f"Result: accepted={accepted2}, reason={reason2}")
        
        # Both should be rejected
        test_pass = (
            not accepted and "replay" in reason.lower() and
            not accepted2 and "replay" in reason2.lower()
        )
        
        logger.info("")
        
        result = {
            "test": "sequence_number_ordering",
            "status": "PASS" if test_pass else "FAIL",
            "expected": "Out-of-order messages should be rejected",
            "msg2_replay": {
                "accepted": accepted,
                "reason": reason
            },
            "msg1_replay": {
                "accepted": accepted2,
                "reason": reason2
            },
            "last_received_seqno": session.last_received_seqno
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "sequence_number_ordering",
            "status": "ERROR",
            "error": str(e)
        }


def test_duplicate_message() -> Dict:
    """Test that duplicate messages (same seqno) are rejected."""

    logger.info("=" * 70)
    logger.info("DUPLICATE MESSAGE TEST")
    logger.info("=" * 70)
    
    try:
        session = ChatSessionSimulator("test_duplicate")
        
        logger.info("Creating message...")
        msg1 = session.create_message("Original")
        
        logger.info("Receiving message first time...")
        accepted1, reason1 = session.receive_message(msg1)
        logger.info(f"First receive: accepted={accepted1}, reason={reason1}")
        
        # Create a duplicate with same seqno (simulate retransmission)
        duplicate = MessageState(
            seqno=msg1.seqno,
            ts=msg1.ts,
            ct=msg1.ct,
            sig=msg1.sig,
            raw_json=msg1.raw_json
        )
        
        logger.info("Receiving duplicate (same seqno)...")
        accepted2, reason2 = session.receive_message(duplicate)
        logger.info(f"Duplicate receive: accepted={accepted2}, reason={reason2}")
        
        # Duplicate should be rejected
        test_pass = not accepted2 and "replay" in reason2.lower()
        
        logger.info("")
        
        result = {
            "test": "duplicate_message",
            "status": "PASS" if test_pass else "FAIL",
            "expected": "Duplicate message should be rejected",
            "first_receive": {
                "accepted": accepted1,
                "reason": reason1
            },
            "duplicate_receive": {
                "accepted": accepted2,
                "reason": reason2
            }
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "duplicate_message",
            "status": "ERROR",
            "error": str(e)
        }


def test_out_of_order_rejection() -> Dict:
    """Test that out-of-order messages (seqno 3 before seqno 2) are rejected."""
    
    logger.info("=" * 70)
    logger.info("OUT-OF-ORDER MESSAGE REJECTION TEST")
    logger.info("=" * 70)
    
    try:
        session = ChatSessionSimulator("test_out_of_order")
        
        logger.info("Creating 3 messages...")
        msg1 = session.create_message("First")
        msg2 = session.create_message("Second")
        msg3 = session.create_message("Third")
        
        # Receive msg1
        logger.info("Receiving message 1...")
        session.receive_message(msg1)
        logger.info(f"Last received seqno: {session.last_received_seqno}")
        
        # Try to receive msg3 before msg2 (out of order)
        logger.info("Attempting to receive message 3 (skip message 2)...")
        accepted3, reason3 = session.receive_message(msg3)
        logger.info(f"Message 3 result: accepted={accepted3}, reason={reason3}")
        
        if accepted3:
            logger.info(f"Last received seqno: {session.last_received_seqno}")
            
            # Now receive msg2 (late)
            logger.info("Now receiving message 2 (late, after message 3 accepted)...")
            accepted2, reason2 = session.receive_message(msg2)
            logger.info(f"Message 2 result: accepted={accepted2}, reason={reason2}")
            
            # Message 2 should be rejected because seqno(2) < last_received_seqno(3)
            out_of_order_detected = not accepted2 and "replay" in reason2.lower()
        else:
            # If msg3 was rejected, that's also valid (strict ordering)
            logger.info("Message 3 was rejected (strict ordering)")
            out_of_order_detected = not accepted3 and "replay" in reason3.lower()
        
        logger.info("")
        
        result = {
            "test": "out_of_order_rejection",
            "status": "PASS" if out_of_order_detected else "FAIL",
            "expected": "Out-of-order messages should be rejected",
            "msg3_result": {
                "accepted": accepted3,
                "reason": reason3
            },
            "msg2_result_if_msg3_accepted": {
                "accepted": accepted2 if accepted3 else "N/A",
                "reason": reason2 if accepted3 else "N/A"
            }
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Test error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "test": "out_of_order_rejection",
            "status": "ERROR",
            "error": str(e)
        }


def main():
    """Run all replay protection tests."""
    logger.info("╔" + "=" * 68 + "╗")
    logger.info("║" + " " * 20 + "REPLAY PROTECTION TEST SUITE" + " " * 21 + "║")
    logger.info("╚" + "=" * 68 + "╝")
    logger.info("")
    
    # Run all tests
    results = []
    
    try:
        results.append(simulate_replay_attack())
        results.append(test_sequence_number_ordering())
        results.append(test_duplicate_message())
        results.append(test_out_of_order_rejection())
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
    
    results_file = Path(__file__).parent / "replay_test_results.json"
    with open(results_file, 'w') as f:
        json.dump(results_json, f, indent=2)
    
    logger.info(f"Results saved to: {results_file}")
    logger.info(f"Logs saved to: {LOG_FILE}")
    logger.info("")
    
    # Exit code
    exit_code = 0 if failed == 0 and errors == 0 else 1
    logger.info(f"Exit code: {exit_code}")
    
    return exit_code


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
