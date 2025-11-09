# Live Integration Tests for SecureChat

Complete guide to running live integration tests that verify actual server/client rejection of tampering, replay attacks, and protocol violations.

---

## 📋 Overview

Live integration tests verify that the **actual implementation** (not mocks) correctly:

- ✅ **Reject replay attacks** (duplicate seqno)
- ✅ **Detect tampering** (modified ciphertext, timestamp, seqno, signature)
- ✅ **Validate certificates** (expired, self-signed, wrong CN)
- ✅ **Enforce message ordering** (reject out-of-order delivery)
- ✅ **Verify signatures** (SIG_FAIL on modification)

Unlike unit tests that simulate behavior, these tests:
1. Start **real server subprocess** (python -m app.server.server)
2. Start **real client subprocess** (python -m app.client.client)
3. Use **MITM proxy** to intercept and modify live network traffic
4. Verify **actual rejection behavior** (connection closes, errors logged)
5. Collect **real PCAP files** and **server logs** as evidence

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    LIVE INTEGRATION TEST                        │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Test Process (pytest or standalone)                           │
│  │                                                              │
│  ├─ [1] Start tcpdump (capture on lo:5000)                    │
│  │       → Output: tests/evidence/live_test.pcap              │
│  │                                                              │
│  ├─ [2] Start real Server subprocess                          │
│  │       → python -m app.server.server                        │
│  │       → Listens on 127.0.0.1:5000                         │
│  │       → Output: tests/evidence/server_live_test.log        │
│  │                                                              │
│  ├─ [3] Start MITM Proxy subprocess                           │
│  │       → Listen on 127.0.0.1:5001                          │
│  │       → Forward to server:5000                             │
│  │       → Can intercept/modify all messages                  │
│  │                                                              │
│  ├─ [4] Start real Client subprocess                          │
│  │       → python -m app.client.client                        │
│  │       → Connects to proxy:5001                             │
│  │       → Output: tests/evidence/client_live_test.log        │
│  │                                                              │
│  ├─ [5] Test 1: REPLAY ATTACK                                 │
│  │       ├─ Inject MSG seqno=1 → server accepts             │
│  │       ├─ Inject MSG seqno=2 → server accepts             │
│  │       ├─ REPLAY MSG seqno=1 → server REJECTS             │
│  │       └─ Verify: Logs contain "REPLAY" or "seqno"        │
│  │                                                              │
│  ├─ [6] Test 2: TAMPERING (ciphertext)                        │
│  │       ├─ Intercept MSG from client                         │
│  │       ├─ Flip 1 bit in base64-encoded ct field           │
│  │       ├─ Forward tampered MSG to server                    │
│  │       └─ Verify: Logs contain "SIG_FAIL"                 │
│  │                                                              │
│  ├─ [7] Test 3: TAMPERING (timestamp)                         │
│  │       ├─ Intercept MSG                                     │
│  │       ├─ Modify ts field (+5000ms)                        │
│  │       ├─ Forward modified MSG                              │
│  │       └─ Verify: Signature verification fails             │
│  │                                                              │
│  ├─ [8] Test 4: TAMPERING (sequence number)                   │
│  │       ├─ Intercept MSG                                     │
│  │       ├─ Increment seqno by 10                            │
│  │       ├─ Forward modified MSG                              │
│  │       └─ Verify: Signature verification fails             │
│  │                                                              │
│  ├─ [9] Test 5: OUT-OF-ORDER DELIVERY                         │
│  │       ├─ Inject MSG seqno=2 first                         │
│  │       ├─ Inject MSG seqno=1 after                         │
│  │       └─ Verify: Server rejects seqno=1 as out-of-order  │
│  │                                                              │
│  ├─ [10] Cleanup                                              │
│  │        ├─ Stop tcpdump                                     │
│  │        ├─ Kill server subprocess                           │
│  │        ├─ Kill client subprocess                           │
│  │        ├─ Stop proxy                                       │
│  │        └─ Collect logs and PCAP                           │
│  │                                                              │
│  └─ [11] Report Results                                       │
│          ├─ Summary of all tests (PASS/FAIL)                 │
│          ├─ Evidence files:                                   │
│          │   - tests/evidence/live_test.pcap                │
│          │   - tests/evidence/server_live_test.log          │
│          │   - tests/evidence/client_live_test.log          │
│          └─ Proxy statistics (messages intercepted/modified) │
│                                                                  │
└────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Run All Live Tests

```bash
# Standalone (no pytest required)
python tests/test_integration_live.py

# With pytest (more detailed)
python -m pytest tests/test_integration_live.py -v -s
```

**Expected Output:**
```
[2024-11-09 15:30:00] INFO - TEST - ======================================================================
[2024-11-09 15:30:00] INFO - TEST - SECURECHAT LIVE INTEGRATION TESTS
[2024-11-09 15:30:00] INFO - TEST - ======================================================================

[2024-11-09 15:30:00] INFO - TEST - 
======================================================================
TEST: Replay Attack (same seqno)
======================================================================
[2024-11-09 15:30:01] INFO - TEST - Starting server...
[2024-11-09 15:30:03] INFO - TEST - ✓ Server started (PID: 12345)
[2024-11-09 15:30:03] INFO - TEST - Starting MITM proxy on port 5001...
[2024-11-09 15:30:04] INFO - TEST - ✓ Proxy started on port 5001
[2024-11-09 15:30:04] INFO - TEST - Injecting MSG seqno=1...
[2024-11-09 15:30:04] INFO - PROXY - INJECTED to server: MSG
[2024-11-09 15:30:04] INFO - TEST - Injecting MSG seqno=2...
[2024-11-09 15:30:05] INFO - PROXY - INJECTED to server: MSG
[2024-11-09 15:30:05] INFO - TEST - REPLAYING MSG seqno=1 (should be rejected)...
[2024-11-09 15:30:05] INFO - PROXY - INJECTED to server: MSG
[2024-11-09 15:30:06] INFO - TEST - ✓ Replay attack test completed
[2024-11-09 15:30:06] INFO - TEST - Proxy stats: {'client_msgs': 0, 'server_msgs': 0, 'bytes_c2s': 0, 'bytes_s2c': 0, 'injected': 3, 'modified': 0}

...

[2024-11-09 15:30:30] INFO - TEST - ======================================================================
TEST SUMMARY
======================================================================
✓ Replay Attack: PASS
✓ Tampering - Ciphertext: PASS
✓ Tampering - Timestamp: PASS
✓ Tampering - Seqno: PASS
✓ Out-of-Order Messages: PASS

Total: 5
Passed: 5
Failed: 0
======================================================================
```

---

## 📖 Test Cases

### Test 1: Replay Attack

**What it tests:** Server correctly rejects messages with duplicate sequence numbers.

**Test flow:**
```
1. Inject MSG with seqno=1, ts=T1
   → Server accepts (first message)

2. Inject MSG with seqno=2, ts=T2
   → Server accepts (seqno=2 > seqno=1)

3. REPLAY: Inject MSG with seqno=1 again
   → Server REJECTS (seqno=1 < expected seqno=3)
   → Logs: "REPLAY DETECTED" or "seqno out of order"
   → Connection may close or error sent
```

**Expected Evidence:**
- Server logs contain "REPLAY" or "seqno"
- Replay message not processed (no RECEIPT sent)

**File:** `tests/test_integration_live.py::TestReplayAttack::test_replay_same_seqno()`

---

### Test 2: Tampering - Ciphertext

**What it tests:** Server detects tampering via signature verification failure.

**Test flow:**
```
1. Client sends: MSG with ct="rB9k3xQ...", sig="jF2kL3M..."
   (Signature is over: seqno || timestamp || ciphertext)

2. Proxy intercepts and MODIFIES:
   - Original ct: "rB9k3xQ..."
   - Tampered ct: "rB9k3xQ..." (flip 1 bit in middle)

3. Server receives modified MSG

4. Server tries to verify signature:
   - Recomputes: Hash(seqno || timestamp || tampered_ct)
   - Compares with received signature
   - MISMATCH! → Signature verification fails

5. Server rejects: "SIG_FAIL"
   - Logs: "Signature verification failed"
   - Sends error message or closes connection
```

**Expected Evidence:**
- Server logs contain "SIG_FAIL" or "Signature failed"
- Message rejected before decryption

**File:** `tests/test_integration_live.py::TestTamperingDetection::test_tamper_ciphertext()`

---

### Test 3: Tampering - Timestamp

**What it tests:** Tampering with any message field is detected via signature.

**Test flow:**
```
1. Client sends: MSG with ts=1731141012000, sig="..."

2. Proxy intercepts and MODIFIES:
   - Original ts: 1731141012000
   - Tampered ts: 1731141017000 (+5000ms)

3. Server receives modified MSG

4. Server verifies signature over (seqno || tampered_ts || ct)
   - MISMATCH with original signature

5. Server rejects: "SIG_FAIL"
```

**Expected Evidence:**
- Server logs contain "SIG_FAIL"
- Tampered timestamp not accepted

**File:** `tests/test_integration_live.py::TestTamperingDetection::test_tamper_timestamp()`

---

### Test 4: Tampering - Sequence Number

**What it tests:** Sequence number is part of message digest and checked in signature.

**Test flow:**
```
1. Client sends: MSG with seqno=1, sig="..."

2. Proxy intercepts and MODIFIES:
   - Original seqno: 1
   - Tampered seqno: 11 (+10)

3. Server receives modified MSG

4. Server verifies signature over (tampered_seqno || timestamp || ct)
   - MISMATCH with original signature

5. Server rejects: "SIG_FAIL"
   - Also reject as out-of-order if seqno jumps too far
```

**Expected Evidence:**
- Server logs contain "SIG_FAIL" or "seqno mismatch"
- Tampered seqno not accepted

**File:** `tests/test_integration_live.py::TestTamperingDetection::test_tamper_seqno()`

---

### Test 5: Out-of-Order Delivery

**What it tests:** Messages delivered out of order are rejected.

**Test flow:**
```
1. Inject MSG with seqno=2 first
   → Server accepts (initial sequence)

2. Inject MSG with seqno=1 after
   → Server REJECTS (1 < last_seqno=2)
   → Logs: "OUT_OF_ORDER" or "seqno out of order"
```

**Expected Evidence:**
- Server logs contain "OUT_OF_ORDER"
- Message with seqno=1 rejected after seqno=2

**File:** `tests/test_integration_live.py::TestOutOfOrderMessages::test_out_of_order()`

---

## 📁 Evidence Files

After running tests, check these files:

### Server Logs
```bash
cat tests/evidence/server_live_test.log
```

**What to look for:**
```
[14:30:00] INFO - Server listening on 127.0.0.1:5000
[14:30:05] DEBUG - Received MSG: seqno=1, ts=1731141012000
[14:30:05] DEBUG - Verifying signature...
[14:30:05] DEBUG - Signature verified ✓
[14:30:06] DEBUG - Received MSG: seqno=1 (REPLAY!)
[14:30:06] ERROR - REPLAY ATTACK DETECTED: seqno=1 already received
[14:30:06] DEBUG - Connection closed
```

### Client Logs
```bash
cat tests/evidence/client_live_test.log
```

**What to look for:**
```
[14:30:02] INFO - Connected to server
[14:30:03] DEBUG - Sending MSG seqno=1
[14:30:03] DEBUG - Message signed and encrypted
[14:30:04] INFO - Receipt received (seqno=1)
[14:30:05] DEBUG - Sending MSG seqno=2
[14:30:05] ERROR - Connection closed by server
```

### PCAP File
```bash
wireshark tests/evidence/live_test.pcap
```

**Filters:**
```
tcp.port == 5000              # All traffic
frame contains "MSG"          # Encrypted messages
frame contains "REPLAY"       # Replay error responses
```

---

## 🔧 Advanced Usage

### Modify a Specific Test

Edit `tests/test_integration_live.py` and modify tampering function:

```python
def tamper_custom(msg):
    """Custom tampering logic."""
    if msg.get('type') == 'MSG':
        # Your custom modification
        msg['custom_field'] = 'modified'
    return msg

env.proxy.on_client_msg = tamper_custom
```

### Add New Test

```python
class TestCustomAttack:
    def test_custom_scenario(self):
        logger.info("TEST: Custom Attack Scenario")
        
        env = LiveTestEnvironment()
        
        try:
            if not env.start_server():
                return False
            if not env.start_proxy():
                return False
            
            # Your test logic here
            msg = {
                'type': 'MSG',
                'seqno': 1,
                'ts': int(time.time() * 1000),
                'ct': 'test',
                'sig': 'test'
            }
            
            env.proxy.inject_to_server(msg)
            time.sleep(1)
            
            return True
        
        finally:
            env.stop_all()
```

---

## 🐛 Troubleshooting

### Issue: "Address already in use"

**Error:** `OSError: [Errno 48] Address already in use`

**Solution:**
```bash
# Kill existing server/proxy
lsof -i :5000
lsof -i :5001
kill -9 <PID>

# Or change ports in test
```

### Issue: "Server failed to start"

**Error:** `Server failed to start`

**Solution:**
```bash
# Check if app.server.server runs standalone
python -m app.server.server

# If error, fix database connection first
python -m app.storage.db --init

# Check .env configuration
cat .env
```

### Issue: "Proxy connection refused"

**Error:** `ConnectionRefusedError: Connection refused`

**Solution:**
```bash
# Ensure server is running on port 5000
# Check if firewall blocks connections
netstat -an | grep 5000

# Verify proxy starts before client
```

### Issue: "No server logs generated"

**Solution:**
```bash
# Capture stdout/stderr manually
python -m app.server.server > tests/evidence/server.log 2>&1

# Or modify test to capture subprocess output
stdout, stderr = env.server_proc.communicate()
print(stdout)
print(stderr)
```

---

## 📊 Test Coverage

| Attack | Test Name | Detection | Evidence |
|--------|-----------|-----------|----------|
| Replay | test_replay_same_seqno | seqno < last_seqno | Server logs "REPLAY" |
| Tamper (ct) | test_tamper_ciphertext | Signature mismatch | Server logs "SIG_FAIL" |
| Tamper (ts) | test_tamper_timestamp | Signature mismatch | Server logs "SIG_FAIL" |
| Tamper (seqno) | test_tamper_seqno | Signature + seqno | Server logs "SIG_FAIL" |
| Out-of-Order | test_out_of_order | seqno validation | Server rejects |

---

## 🎯 Verification Checklist

After running tests, verify:

- [ ] All 5 tests marked as PASS
- [ ] Server logs exist: `tests/evidence/server_live_test.log`
- [ ] PCAP file exists: `tests/evidence/live_test.pcap`
- [ ] Proxy statistics show messages processed
- [ ] Server logs contain rejection keywords:
  - REPLAY
  - SIG_FAIL
  - OUT_OF_ORDER
  - BAD_CERT
- [ ] No uncaught exceptions in test output

---

## 📚 Related Documentation

- **Unit Tests**: `tests/test_invalid_cert.py`, `tests/test_replay.py`, `tests/test_tampering.py`
- **Wireshark Analysis**: `tests/WIRESHARK_QUICK_START.md`
- **MITM Proxy Source**: `tests/mitm_proxy.py`
- **Integration Test Source**: `tests/test_integration_live.py`
- **Main README**: `README.md`

---

## Summary

Live integration tests verify that your **actual implementation** (not mocks):

✅ Rejects **replay attacks** with sequence number validation  
✅ Detects **tampering** via cryptographic signatures  
✅ Validates **message ordering** and rejects out-of-order delivery  
✅ Properly **logs security events** for forensics  
✅ **Closes connections** on protocol violations  

These tests provide **real, repeatable evidence** that your SecureChat implementation is secure against common network attacks.

Run them with:
```bash
python tests/test_integration_live.py
```

For more details, see the test source code in `tests/test_integration_live.py` and `tests/mitm_proxy.py`.
