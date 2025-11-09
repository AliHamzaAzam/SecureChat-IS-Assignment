# SecureChat Network Traffic Analysis Guide

This guide explains how to capture and analyze SecureChat network traffic to verify cryptographic properties and protocol security.

## Quick Start

### Prerequisites

Install required tools:

```bash
# macOS
brew install wireshark tcpdump

# Linux
sudo apt-get install wireshark tcpdump

# Python dependencies (already in requirements.txt)
pip install -r requirements.txt
```

## Step 1: Manual PCAP Capture

**Terminal 1: Start SecureChat Server**
```bash
python -m app.server.server
```

**Terminal 2: Start Packet Capture**
```bash
sudo tcpdump -i lo0 -w tests/evidence/secure_chat.pcapng port 9999
```

> **Note**: On macOS, use `lo0` (not `lo` on Linux)

**Terminal 3: Run Client and Chat**
```bash
python -m app.client.client
```

In the client, perform these actions:
1. **Register** a new user (e.g., `alice@example.com` / `password123`)
2. **Login** with the same credentials
3. **Send encrypted messages**:
   - "Hello, this is a secret message"
   - "Testing end-to-end encryption"
4. **Type `exit`** to disconnect

**Terminal 2: Stop Capture**
```bash
# Press Ctrl+C to stop tcpdump
```

This generates: `tests/evidence/secure_chat.pcapng` (~50-500 KB depending on chat volume)

---

## Step 2: Analyze PCAP File

### List Available PCAP Files

```bash
python tests/wireshark_capture.py list
```

### Analyze a Specific PCAP

```bash
python tests/wireshark_capture.py analyze tests/evidence/secure_chat.pcapng
```

This generates three analysis files in `tests/evidence/`:
- `capture_analysis.json` - Structured packet data
- `capture_analysis.txt` - Human-readable report
- `capture_analysis_manifest.json` - Metadata

---

## Understanding the Analysis Output

### Sample Console Output

The script outputs a summary like:

```
SECURECHAT PCAP ANALYZER
======================================================================

[INFO] Analyzing PCAP: tests/evidence/secure_chat.pcapng
[INFO] File size: 127450 bytes
[✓] Extracted 12 packets from PCAP

SECURECHAT PCAP ANALYSIS REPORT
======================================================================
Timestamp: 2025-11-10T15:32:45.123456
PCAP File: tests/evidence/secure_chat.pcapng
File Size: 127450 bytes

PROTOCOL MESSAGE SUMMARY
----------------------------------------------------------------------
  HELLO: 1 packet(s)
  SERVER_HELLO: 1 packet(s)
  DH_CLIENT: 1 packet(s)
  DH_SERVER: 1 packet(s)
  MSG: 4 packet(s)

SECURITY FINDINGS
======================================================================
✅ All 4 MSG packets are encrypted (confidentiality verified)
✅ All 4 MSG packets are signed (integrity verified)
✅ DH key exchange detected (2 packets)
✅ Certificate exchange completed (HELLO/SERVER_HELLO)

Total packets captured: 12
```

### Key Verification Points

✅ **Confidentiality** 
- All MSG packets have encrypted ciphertext

✅ **Integrity**
- All MSG packets have RSA-PSS signatures

✅ **Authenticity**
- HELLO/SERVER_HELLO packets contain X.509 certificates

✅ **Anti-Replay**
- Each MSG has unique sequence number

✅ **Non-Repudiation**
- RECEIPT packets contain signed transcript hash

---

## Analysis Output Files

### 1. capture_analysis.txt

Human-readable report including:
- Protocol message sequence (HELLO → DH_* → MSG → RECEIPT)
- Encryption status per packet
- Signature verification status
- Security findings

### 2. capture_analysis.json

Structured data for programmatic analysis

### 3. capture_analysis_manifest.json

Metadata and file locations

---

## Wireshark GUI Inspection

To manually inspect the PCAP file in the Wireshark graphical interface, use these filters:

**Show all SecureChat traffic:**
```
tcp.port == 9999
```

**Show only encrypted messages:**
```
tcp contains "MSG"
```

**Show DH key exchange:**
```
tcp contains "DH_"
```

**Follow entire conversation:**
Right-click any packet → "Follow TCP Stream" to see all related packets in sequence

---

## Expected Protocol Sequence

A complete SecureChat session should show this packet order:

```
Frame 1:  HELLO (client → server)
          - Client certificate
          - Client nonce

Frame 2:  SERVER_HELLO (server → client)
          - Server certificate
          - Server nonce

Frame 3:  DH_CLIENT (client → server)
          - Client DH public key

Frame 4:  DH_SERVER (server → client)
          - Server DH public key

Frames 5-N: MSG (bidirectional)
          - Encrypted: Yes (ciphertext in "ct")
          - Signed: Yes (signature in "sig")
          - Sequence numbers: 1, 2, 3, ...

Frame N+1: RECEIPT (client ← → server)
          - Session ID
          - Transcript hash (signed)
```

---

## Security Verification Checklist

After analyzing a PCAP file, verify these properties:

- [ ] **HELLO/SERVER_HELLO packets present** (certificate exchange)
- [ ] **DH_CLIENT/DH_SERVER packets present** (key agreement)
- [ ] **All MSG packets encrypted** (ciphertext present)
- [ ] **All MSG packets signed** (signature present)
- [ ] **MSG sequence numbers increment** (1, 2, 3, ...)
- [ ] **RECEIPT packet present** (non-repudiation)
- [ ] **No unencrypted user data** (text messages not visible)
- [ ] **Certificate CN matches expected identity**
- [ ] **All fields properly populated**

---

## Verification in Wireshark GUI

When viewing captured packets in Wireshark GUI, look for these properties:

### Certificate Exchange Packets (HELLO/SERVER_HELLO)

**Expected appearance:**
- Plaintext (not encrypted, as certificates are public)
- Contains BEGIN CERTIFICATE...END CERTIFICATE markers
- Should see certificate data in hex view

**What to verify:**
- Certificates are present
- CN (Common Name) matches expected server/client identity

### DH Key Exchange Packets (DH_CLIENT/DH_SERVER)

**Expected appearance:**
- Large hexadecimal values (DH public keys)
- JSON format with public key data
- Plaintext (public key exchange)

**What to verify:**
- Both client and server packets present
- Keys are properly formed numbers

### Encrypted Message Packets (MSG)

**Expected appearance:**
- Contains `"ct":"..."` field with base64 encoded data
- Contains `"sig":"..."` field with RSA signature
- The ciphertext should look like random base64 (alphanumeric + /+=)

**What to verify:**
- Ciphertext is NOT readable plaintext (should be binary encoded)
- Signature present on all messages
- Sequence numbers increment (1, 2, 3...)

---

## Command Reference

The following commands are available for analysis:

```bash
# List available PCAP files in tests/evidence/
python tests/wireshark_capture.py list

# Analyze a captured PCAP file
python tests/wireshark_capture.py analyze tests/evidence/secure_chat.pcapng

# Analyze with custom output name
python tests/wireshark_capture.py analyze <path> -o custom_name

# Show help
python tests/wireshark_capture.py --help
```

Generated analysis files appear in `tests/evidence/`:
- `capture_analysis.json` - Structured packet data
- `capture_analysis.txt` - Human-readable report
- `capture_analysis_manifest.json` - Metadata

---

## What Gets Verified

✅ **Confidentiality** - Chat messages are encrypted (AES-128-CBC)  
✅ **Integrity** - Messages have RSA-PSS signatures  
✅ **Authenticity** - DH key exchange with certificate validation  
✅ **Non-Repudiation** - Session receipts prove message delivery  
✅ **Replay Prevention** - Sequence numbers prevent replays  

---

## References

- **tcpdump**: https://www.tcpdump.org/
- **Wireshark**: https://www.wireshark.org/
- **tshark** (CLI): https://www.wireshark.org/docs/man-pages/tshark.html
- **SecureChat Protocol**: See `MESSAGE_FLOW.md`
