# Replay Protection Test Suite

## Overview

The **Replay Protection Test Suite** (`tests/test_replay.py`) demonstrates that SecureChat's sequence number-based replay attack protection works correctly.

A **replay attack** occurs when an attacker captures a valid message and sends it again later, potentially causing the server to process it a second time. SecureChat prevents this using monotonically increasing sequence numbers.

---

## Quick Start

### Running the Test
```bash
python tests/test_replay.py
```

### Expected Output
```
✓ Test 1: Replay Attack Simulation - PASS
✓ Test 2: Sequence Number Ordering - PASS
✓ Test 3: Duplicate Message Rejection - PASS
✓ Test 4: Out-of-Order Rejection - PASS

Total: 4, Passed: 4 ✓, Failed: 0 ✗, Errors: 0 ⚠
Exit code: 0
```

### Output Files Generated
```
tests/
├── replay_test.log               # Detailed execution log
├── replay_test_results.json      # Structured results
└── REPLAY_PROTECTION_README.md   # This file
```

---

## Protection Mechanism

### Algorithm
```
For each incoming message:
  IF message.seqno <= receiver.last_received_seqno:
    REJECT as REPLAY attack
  ELSE:
    ACCEPT message
    UPDATE receiver.last_received_seqno = message.seqno
```

### Key Points
- Sequence numbers MUST be strictly increasing
- Receiver tracks `last_received_seqno` per session
- Any message with `seqno ≤ last_received_seqno` is automatically rejected
- Works regardless of network delays or message ordering

---

## Attack Scenarios & Test Cases

### Normal Chat (No Attack)
```
Timeline:
  Sender    │  Message  │  Seqno  │  Receiver State
────────────┼───────────┼─────────┼─────────────────────────────────
  msg 1     │  "Hi"     │   1     │  last_received=1 ✓
  msg 2     │  "How r?" │   2     │  last_received=2 ✓
  msg 3     │  "Good"   │   3     │  last_received=3 ✓
```

### Replay Attack (What We Prevent)
```
Timeline with Attacker:
  Sender    │  Message  │  Seqno  │  Attacker     │  Receiver State
────────────┼───────────┼─────────┼───────────────┼──────────────────
  msg 1     │  "Hi"     │   1     │  [capture]    │  last_received=1 ✓
  msg 2     │  "How r?" │   2     │               │  last_received=2 ✓
  msg 3     │  "Good"   │   3     │  ← CAPTURED   │  last_received=3 ✓
  msg 4     │  "Bye"    │   4     │               │  last_received=4 ✓
  msg 5     │  "Later"  │   5     │               │  last_received=5 ✓
            │           │         │  replay msg3→ │  Check: 3 ≤ 5? YES → ❌ REJECT
```

---

## Test Cases

### ✓ Test 1: Replay Attack Simulation

**Scenario:**
- Send 3 normal messages (seqno 1, 2, 3)
- Capture message 3
- Send 2 more messages (seqno 4, 5)
- Replay captured message 3
- Expect: Rejection with error

**Expected Output:**
```
--- Phase 1: Normal Messages ---
✓ Message accepted: seqno=1
✓ Message accepted: seqno=2
✓ Message accepted: seqno=3
✓ Captured message 3 (seqno=3) for replay
  Last received seqno: 3

--- Phase 2: More Normal Messages ---
✓ Message accepted: seqno=4
  Last received seqno: 4
✓ Message accepted: seqno=5
  Last received seqno: 5

--- Phase 3: Replay Attack ---
Replaying captured message 3 (seqno=3)...
  Current last_received_seqno: 5
❌ REPLAY ATTACK: Replay detected: seqno=3 ≤ last_received_seqno=5

Message accepted: False
Reason: Replay detected: seqno=3 ≤ last_received_seqno=5

STATUS: ✓ PASS
```

**Security Property Tested:**
- Once a sequence number is accepted, any earlier seqno is permanently rejected
- Time-shifted replay attacks are caught

---

### ✓ Test 2: Sequence Number Ordering

**Scenario:**
- Receive 3 messages in order (seqno 1, 2, 3)
- Try to receive message 2 again
- Try to receive message 1 again
- Expect: Both replays rejected

**Expected Output:**
```
Receiving messages in order (seqno 1, 2, 3)...
✓ Message accepted: seqno=1
✓ Message accepted: seqno=2
✓ Message accepted: seqno=3

Attempting to receive message 2 again...
❌ REPLAY ATTACK: Replay detected: seqno=2 ≤ last_received_seqno=3

Attempting to receive message 1 again...
❌ REPLAY ATTACK: Replay detected: seqno=1 ≤ last_received_seqno=3

STATUS: ✓ PASS
```

**Security Property Tested:**
- The receiver never needs to maintain a history of all received seqnos
- Just one counter (`last_received_seqno`) is sufficient
- Ordering is permanently enforced

---

### ✓ Test 3: Duplicate Message Rejection

**Scenario:**
- Receive message with seqno=1
- Immediately receive another message with seqno=1 (network retransmission)
- Expect: Duplicate rejected

**Expected Output:**
```
Creating message...
Receiving message first time...
✓ Message accepted: seqno=1
First receive: accepted=True, reason=OK

Receiving duplicate (same seqno)...
❌ REPLAY ATTACK: Replay detected: seqno=1 ≤ last_received_seqno=1
Duplicate receive: accepted=False

STATUS: ✓ PASS
```

**Real-World Application:**
- TCP can retransmit packets if ACK is lost
- Application layer must not accept duplicate messages
- This test shows duplicates are caught correctly

---

### ✓ Test 4: Out-of-Order Message Rejection

**Scenario:**
- Receive message 1
- Try to receive message 3 (skip message 2)
  - Message 3 is accepted (3 > 1)
  - Now `last_received=3`
- Try to receive message 2 (late arrival)
  - Message 2 is rejected (2 ≤ 3)
- Expect: Late message rejected

**Expected Output:**
```
Receiving message 1...
✓ Message accepted: seqno=1
Last received seqno: 1

Attempting to receive message 3 (skip message 2)...
✓ Message accepted: seqno=3
Message 3 result: accepted=True, reason=OK
Last received seqno: 3

Now receiving message 2 (late, after message 3 accepted)...
❌ REPLAY ATTACK: Replay detected: seqno=2 ≤ last_received_seqno=3
Message 2 result: accepted=False

STATUS: ✓ PASS
```

**Security Property Tested:**
- Once a higher seqno is accepted, all lower seqnos are permanently rejected
- Out-of-order processing attacks are prevented
- Ordering is guaranteed at protocol level

---

## Attack Scenarios Prevented

### 1. Simple Replay Attack
```
Attacker: [capture msg3] → [send msg3 again 10 seconds later]
Receiver: last_received=3 → [seqno=3 ≤ 3] → REJECT
```

### 2. Out-of-Order Attack
```
Normal order:   msg1 (seqno1) → msg2 (seqno2) → msg3 (seqno3)
Attack order:   msg3 (seqno3) → msg1 (seqno1) → msg2 (seqno2)
Protection:     seqno3 ✓ → seqno1 ✗ (1 ≤ 3) → seqno2 ✗ (2 ≤ 3)
```

### 3. Duplicate Transmission
```
Normal: [send msg1] → [lost ACK] → [retransmit msg1]
Receiver: seqno1 ✓ → seqno1 ✗ (1 ≤ 1) → duplicate caught
```

### 4. Delayed Message Arrival
```
Timeline: send msg1 → send msg2 → receive msg2 (seqno=2) ✓
          late arrival of msg1 (seqno=1) → 1 ≤ 2 → REJECT
```

---

## Test Results Summary

### All Tests: 4/4 PASS ✅

```
================================================================================
TEST SUMMARY
================================================================================
Total: 4
Passed: 4 ✓
Failed: 0 ✗
Errors: 0 ⚠

Results saved to: tests/replay_test_results.json
Logs saved to: tests/replay_test.log

Exit code: 0
```

### JSON Results File
Results are saved to `tests/replay_test_results.json`:

```json
{
  "timestamp": "2025-11-09T20:14:41",
  "summary": {
    "total": 4,
    "passed": 4,
    "failed": 0,
    "errors": 0
  },
  "results": [
    {
      "test": "replay_attack",
      "status": "PASS",
      "expected": "Replay message should be rejected",
      "actual": "Message accepted=False, Reason=Replay detected: seqno=3 ≤ last_received_seqno=5",
      "replay_detected": true,
      "captured_seqno": 3,
      "last_received_seqno": 5
    },
    ...
  ]
}
```

---

## Implementation in SecureChat

### Protocol Definition (`app/common/protocol.py`)
```python
@dataclass
class ChatMsg:
    type: str       # "MSG"
    seqno: int      # Sequence number (increments per message)
    ts: int         # Timestamp in milliseconds
    ct: str         # Base64 ciphertext
    sig: str        # Base64 RSA-PSS signature
```

### Client-Side (`app/client/client.py`)
```python
message_counter = 0

def send_message(text):
    global message_counter
    message_counter += 1
    
    msg = ChatMsg(
        type="MSG",
        seqno=message_counter,
        ts=int(time.time() * 1000),
        ct=encrypt(text),
        sig=sign(text)
    )
    # send msg
```

### Server-Side (`app/server/server.py`)
```python
class ClientSession:
    def __init__(self):
        self.last_received_seqno = 0
    
    def receive_message(self, msg: ChatMsg):
        if msg.seqno <= self.last_received_seqno:
            raise ReplayAttackError(
                f"Replay detected: seqno={msg.seqno} ≤ {self.last_received_seqno}"
            )
        
        self.last_received_seqno = msg.seqno
        # process message
```

---

## Security Properties Verified

| Property | Test | Status |
|----------|------|--------|
| **Replay Detection** | Test 1: Replay Attack | ✓ PASS |
| **Ordering Enforcement** | Test 2: Sequence Number Ordering | ✓ PASS |
| **Duplicate Prevention** | Test 3: Duplicate Message | ✓ PASS |
| **Out-of-Order Rejection** | Test 4: Out-of-Order Rejection | ✓ PASS |

---

## Integration with CIANR Properties

SecureChat achieves complete CIANR security (Confidentiality, Integrity, Authenticity, Non-Repudiation, & Replay Prevention):

| Property | Mechanism | Test File |
|----------|-----------|-----------|
| **Confidentiality** | AES-128-CBC encryption | `test_encrypted_messages.py` |
| **Integrity** | HMAC in message signature | `test_encrypted_messages.py` |
| **Authenticity** | RSA-PSS signature verification | `test_invalid_cert.py` |
| **Non-Repudiation** | Signed receipts + transcript | `scripts/verify_session.py` |
| **Replay Protection** | Sequence number checking | `tests/test_replay.py` ← YOU ARE HERE |

---

## Limitations & Future Improvements

### Current Approach
✓ Simple and efficient (O(1) memory, O(1) time)
✓ Works for in-order message processing
✓ Sufficient for single TCP connection

### Limitations
- Doesn't handle very large seqno ranges (though 2^31 messages is sufficient)
- Assumes messages are processed in TCP arrival order
- Would need enhancement for multi-path delivery

### Future Enhancements
1. **Session timeout**: Reset seqno counter after session idle time
2. **Seqno wrapping**: Handle seqno overflow gracefully
3. **Out-of-order window**: Accept small window of out-of-order messages (jitter buffer)
4. **Per-direction tracking**: Track separate seqno for client→server and server→client

---

## Troubleshooting FAQ

### Q: Why use sequence numbers instead of timestamps?
**A:** Sequence numbers are:
- Deterministic (no clock sync needed)
- Efficient (simple counter increment)
- Immune to clock attacks
- Work across network delays

### Q: What if a message is received out of order due to network delay?
**A:** SecureChat uses TCP which preserves in-order delivery. Messages cannot arrive out of order unless:
- The application layer allows it
- Or the transport is UDP (not used in SecureChat)

### Q: Can the sequence number overflow?
**A:** Theoretically yes, but:
- 32-bit seqno = 4.3 billion messages
- Even at 1000 msg/sec = 50+ days per session
- In practice, sessions are much shorter

### Q: How is this different from non-repudiation?
**A:**
- **Non-Repudiation**: Proves who sent it and they can't deny it (via signatures)
- **Replay Prevention**: Ensures the same message isn't processed twice (via seqno)

Both are needed for secure messaging.

### Q: What happens if the receiver crashes?
**A:** In a crash scenario:
- Receiver loses `last_received_seqno` state
- On reconnect, seqno counter restarts from 1
- This is acceptable because:
  - Each connection is a separate session
  - TCP provides sequence guarantees within a connection
  - New session = fresh security context

---

## Files Generated

After running the test, the following files are created/updated:

```
tests/
├── test_replay.py                    (Main test file - 600+ lines)
├── replay_test.log                   (Detailed execution log)
├── replay_test_results.json          (JSON results - 4/4 PASS)
└── REPLAY_PROTECTION_README.md       (This file)
```

---

## References

- **RFC 2104**: HMAC Message Authentication Code
- **RFC 3610**: AES-CCM
- **RFC 6090**: Fundamental ECC Algorithms
- **NIST SP 800-38A**: Recommendation for Block Cipher Modes of Operation
- **OWASP**: Replay Attack Prevention
- **Cryptography library**: https://cryptography.io/

---

**Last Updated:** 2025-11-09  
**Test Status:** ✅ All 4 Tests Passing  
**Exit Code:** 0 (Success)
