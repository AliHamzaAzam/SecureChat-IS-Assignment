# Wireshark Network Analysis - Quick Start Guide

## Overview

This guide shows how to capture and analyze SecureChat network traffic to verify that:
- ✅ Messages are encrypted on the wire
- ✅ No plaintext is visible in packets
- ✅ Certificate exchange is secure
- ✅ DH key exchange is properly signed
- ✅ All authenticated messages have valid signatures

---

## Prerequisites

### Install Required Tools
```bash
# macOS
brew install tcpdump wireshark

# Linux (Ubuntu/Debian)
sudo apt-get install tcpdump wireshark

# Verify installation
tcpdump --version
wireshark --version
```

### Note on Permissions
- `tcpdump` requires `sudo` privilege to capture packets
- You'll be prompted for your password during capture

---

## Quick Start (Automated)

### Option 1: Full Automated Capture & Analysis
```bash
cd /Users/azaleas/Developer/Github/SecureChat-IS-Assignment

# Start capture, server, and wait for manual testing
python tests/wireshark_capture.py --mode full
```

**What this does:**
1. ✓ Starts server automatically
2. ✓ Starts tcpdump packet capture (requires sudo)
3. ✓ Waits for you to run client and test
4. ✓ Generates analysis report
5. ✓ Opens PCAP in Wireshark

---

## Manual Process (Recommended for Control)

### Step 1: Open Terminal 1 - Start Server
```bash
cd /Users/azaleas/Developer/Github/SecureChat-IS-Assignment
python -m app.server.server
```

**Expected output:**
```
[INFO] Server starting on 127.0.0.1:5000
[INFO] Listening for connections...
```

### Step 2: Open Terminal 2 - Start Packet Capture
```bash
cd /Users/azaleas/Developer/Github/SecureChat-IS-Assignment
sudo tcpdump -i lo -w tests/evidence/secure_chat.pcap port 5000
```

**What to expect:**
- Will prompt for your password (sudo)
- Will show: `tcpdump: listening on lo...`
- Will wait silently for packets

### Step 3: Open Terminal 3 - Run Client
```bash
cd /Users/azaleas/Developer/Github/SecureChat-IS-Assignment
python -m app.client.client
```

### Step 4: Perform Test Workflow

**In the client terminal, follow these prompts:**

```
=== SecureChat Client ===
Enter username: testuser
Enter password: testpass123

Menu:
1. Register
2. Login
3. Send Message
4. Logout

Choice: 1  [REGISTER - creates new account]

Username: testuser
Password: testpass123
Confirm Password: testpass123

✓ Registered successfully

Choice: 2  [LOGIN]
Username: testuser
Password: testpass123

✓ Logged in

Choice: 3  [SEND MESSAGE]
Message: Hello, this is a secret message
> [Server receives encrypted message]

Choice: 3  [SEND ANOTHER]
Message: Another encrypted message
> [Server receives encrypted message]

Choice: 3  [SEND ANOTHER]
Message: Testing end-to-end encryption
> [Server receives encrypted message]

Choice: 4  [LOGOUT]
> [Receives session receipt]
> [Connection closed]
```

### Step 5: Stop Packet Capture

**In Terminal 2 (tcpdump):**
- Press `Ctrl+C`
- Will show capture summary:
  ```
  1234 packets captured
  1234 packets received by filter
  0 packets dropped by kernel
  ```

### Step 6: Open PCAP in Wireshark

```bash
# Opens the captured PCAP file
wireshark tests/evidence/secure_chat.pcap
```

---

## Analyzing Traffic in Wireshark

### Step 1: Apply Basic Filter
```
tcp.port == 5000
```
Shows all packets for the chat session.

### Step 2: Find Encrypted Messages
```
tcp.port == 5000 && frame contains "MSG"
```
Shows only the chat messages (which should all be encrypted).

### Step 3: Examine a Message Packet

1. Click on any MSG packet
2. Expand the "Data" section in packet details
3. Look at the JSON payload:

```json
{
  "type": "MSG",
  "seqno": 1,
  "ts": 1762701764295,
  "ct": "lN3P+/7ZqK2J8xY0M9vQ1A==...",
  "sig": "6h2oXtW7fRj5LhxzUygK0pgn+vRStfwMDy+EQbdmYE4=..."
}
```

**Verify:**
- ✓ `ct` field is base64 (not readable)
- ✓ `sig` field is present (message authenticated)
- ✗ No plaintext message visible
- ✗ Cannot decode `ct` without session key

### Step 4: Look at Certificate Exchange

```
tcp.port == 5000 && frame contains "HELLO"
```

**You should see:**
- HELLO message with client certificate
- SERVER_HELLO message with server certificate
- Both certificates are PEM-formatted (OK - they're public)

### Step 5: Examine DH Key Exchange

```
tcp.port == 5000 && frame contains "DH"
```

**You should see:**
- DH_CLIENT with 2048-bit public key (hex string)
- DH_SERVER with different 2048-bit public key
- Both messages signed with RSA-PSS signatures

### Step 6: Follow Complete Conversation

1. Click on any packet
2. Right-click → **Follow TCP Stream**
3. Shows entire session in one view
4. Color-coded:
   - **Red:** Client → Server
   - **Blue:** Server → Client

---

## Expected Findings

### Packet Timeline
```
Frame 1-3:   TCP Handshake (SYN, SYN-ACK, ACK)
Frame 4:     HELLO (client certificate + nonce)
Frame 5:     SERVER_HELLO (server certificate + nonce)
Frame 6:     REGISTER/LOGIN (username + hashed password)
Frame 7:     DH_CLIENT (public key #1 + signature)
Frame 8:     DH_SERVER (public key #2 + signature)
             [Session key now established]
Frame 9:     MSG (seqno=1, encrypted message #1)
Frame 10:    MSG (seqno=1, encrypted message #2)
Frame 11:    MSG (seqno=2, encrypted message #3)
Frame 12:    RECEIPT (transcript hash + signature)
Frame 13:    TCP FIN (connection close)
```

### Key Observations

✅ **Before DH Exchange:**
- Plaintext allowed (certificates are public)
- Passwords are hashed (not plaintext)

✅ **After DH Exchange:**
- ALL message payloads are encrypted
- No plaintext visible in any MSG packet
- Each message has unique `ct` value (different ciphertext per message)

✅ **Signatures:**
- Every message has `sig` field
- Signature size is consistent (~256 bytes base64)

✅ **Sequence Numbers:**
- `seqno` starts at 1 and increments
- No gaps or duplicates

---

## Taking Screenshots

### Screenshot 1: Full Packet List
```bash
# In Wireshark
1. View → Layout → Packet List / Packet Details / Packet Bytes
2. Apply filter: tcp.port == 5000
3. Click View → Zoom → Zoom In (make text larger)
4. Screenshot: CMD+Shift+3 (macOS) or use Wireshark's File → Export
5. Save as: tests/evidence/wireshark_overview.png
```

### Screenshot 2: Encrypted Message Detail
```bash
# In Wireshark
1. Filter: tcp.port == 5000 && frame contains "MSG"
2. Click on a MSG packet
3. Expand Data section to show JSON
4. Highlight the "ct" field in Packet Details
5. Bottom pane should show base64 bytes
6. Screenshot: Save as tests/evidence/wireshark_msg_packet.png
```

### Screenshot 3: DH Key Exchange
```bash
# In Wireshark
1. Filter: tcp.port == 5000 && frame contains "DH_CLIENT"
2. Expand Data to show public key (hex string)
3. Scroll down to show signature
4. Switch to DH_SERVER frame
5. Show different key + signature
6. Screenshot: Save as tests/evidence/wireshark_dh_exchange.png
```

### Screenshot 4: Follow TCP Stream
```bash
# In Wireshark
1. Click any packet
2. Right-click → Follow TCP Stream
3. Expand window to show full conversation
4. Highlight encrypted sections in red
5. Screenshot: Save as tests/evidence/wireshark_tcp_stream.png
```

---

## Verification Checklist

- [ ] PCAP file exists: `ls -lh tests/evidence/secure_chat.pcap`
- [ ] PCAP file > 10KB (should have captured significant data)
- [ ] All MSG packets have `ct` field (ciphertext)
- [ ] No plaintext messages visible in any packet
- [ ] DH public keys are different (not same key)
- [ ] RSA signatures present on authenticated messages
- [ ] Certificate exchange shows valid X.509 certs
- [ ] Sequence numbers are strictly increasing
- [ ] Connection closes with RECEIPT packet

---

## Common Issues

### Issue: "Permission denied" when running tcpdump
**Solution:**
```bash
sudo tcpdump -i lo -w tests/evidence/secure_chat.pcap port 5000
# Enter your password when prompted
```

### Issue: "No packets captured"
**Solution:**
1. Verify server is running on port 5000: `lsof -i :5000`
2. Verify client connects to port 5000
3. Verify tcpdump is using correct interface: `ifconfig lo0`

### Issue: "Cannot open PCAP in Wireshark"
**Solution:**
```bash
# Try from command line
wireshark tests/evidence/secure_chat.pcap

# Or drag-and-drop file into Wireshark window
open tests/evidence/secure_chat.pcap -a Wireshark
```

### Issue: "JSON not showing in Wireshark"
**Solution:**
1. Right-click packet → **Decode As → HTTP**
2. Or manually examine raw bytes section at bottom
3. Base64 content is visible as-is

---

## Next Steps

After capturing traffic:

1. **Analyze with Wireshark** - Follow steps above
2. **Export analysis** - File → Export As → Plain Text
3. **Document findings** - Create analysis report
4. **Generate screenshots** - Save key packet views
5. **Create evidence file** - Document what you found

---

## File Locations

After running capture:
```
tests/
├── evidence/
│   ├── secure_chat.pcap              ← Binary PCAP capture
│   ├── secure_chat_analysis.txt      ← Text analysis
│   ├── capture_manifest.json         ← Metadata
│   └── wireshark_*.png               ← Screenshots
├── WIRESHARK_ANALYSIS.md             ← This guide
└── wireshark_capture.py              ← Capture script
```

---

## Additional Resources

- **Wireshark Official Guide**: https://www.wireshark.org/docs/wsug/
- **tcpdump Manual**: https://www.tcpdump.org/papers/sniffing-faq.html
- **TCP/IP Protocol**: https://en.wikipedia.org/wiki/Internet_protocol_suite
- **JSON in HTTP**: RFC 7158

---

**Ready to analyze your secure chat traffic? Start with Step 1!**
