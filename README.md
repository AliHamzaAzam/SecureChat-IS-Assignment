# SecureChat – Console-Based PKI-Enabled Secure Chat System

A comprehensive implementation of a **console-based, application-layer secure chat system** in **Python** demonstrating cryptographic principles:  
**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

---

## 📚 Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Starting the Server](#starting-the-server)
  - [Starting a Client](#starting-a-client)
  - [Registration Flow](#registration-flow)
  - [Login and Chat](#login-and-chat)
  - [Sample I/O Examples](#sample-io-examples)
- [Security Features](#security-features)
- [Testing](#testing)
  - [Unit Tests](#unit-tests)
  - [Network Analysis](#network-analysis)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

---

## Prerequisites

Ensure you have the following installed on your system:

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.8+ | Runtime environment |
| MySQL | 8.0+ | User database and session storage |
| OpenSSL | 1.1.1+ | Certificate generation and validation |
| pip | Latest | Python package management |
| Git | Latest | Version control |

### Check Your System

```bash
# Check Python version
python3 --version          # Should output 3.8 or higher

# Check MySQL availability
mysql --version            # Should output MySQL 8.0 or higher

# Check OpenSSL
openssl version            # Should output OpenSSL 1.1.1 or higher
```

If MySQL is not installed locally, use Docker (recommended):
```bash
docker --version           # Verify Docker is installed
```

---

## Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SECURECHAT SYSTEM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────────┐              ┌──────────────────────┐ │
│  │   CLIENT MACHINE     │              │   SERVER MACHINE     │ │
│  │                      │              │                      │ │
│  │  ┌────────────────┐  │ TCP Port     │  ┌────────────────┐ │ │
│  │  │ User Interface │  │ 5000 (TCP)   │  │ Session Manager│ │ │
│  │  │                │  │◄────────────►│  │                │ │ │
│  │  └────────────────┘  │              │  └────────────────┘ │ │
│  │         ▲            │              │         ▲            │ │
│  │         │ Socket I/O │              │         │ Socket I/O │ │
│  │         ▼            │              │         ▼            │ │
│  │  ┌────────────────┐  │              │  ┌────────────────┐ │ │
│  │  │ Crypto Layer   │  │              │  │ Crypto Layer   │ │ │
│  │  │ (AES, RSA, DH) │  │              │  │ (AES, RSA, DH) │ │ │
│  │  └────────────────┘  │              │  └────────────────┘ │ │
│  │                      │              │                      │ │
│  │ Certs:              │              │ Certs:              │ │
│  │ • client_cert.pem   │              │ • server_cert.pem   │ │
│  │ • client_key.pem    │              │ • server_key.pem    │ │
│  │ • ca_cert.pem       │              │ • ca_cert.pem       │ │
│  └──────────────────────┘              └──────────────────────┘ │
│                                                                   │
│  Protocol Layer: Application-Level Encryption                    │
│  • Message Format: [4-byte length prefix] + [JSON message]       │
│  • Encryption: AES-128-CBC with RSA-PSS-SHA256 signatures        │
│  • Key Exchange: Diffie-Hellman (RFC 3526 Group 14, 2048-bit)   │
│                                                                   │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 │ JDBC/MySQL Network
                 │ (Salted SHA-256 passwords)
                 │
         ┌───────▼────────┐
         │  MYSQL DATABASE │
         │                 │
         │ Tables:        │
         │ • users        │
         │ • sessions     │
         │ • transcripts  │
         └─────────────────┘

Security Properties:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Confidentiality: AES-128-CBC encryption on all messages
✓ Integrity: RSA-PSS-SHA256 signatures (seqno || timestamp || ciphertext)
✓ Authenticity: X.509 mutual certificate validation
✓ Non-Repudiation: Signed receipts + append-only session transcripts
✓ Replay Prevention: Monotonically increasing sequence numbers
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Message Protocol Flow

```
Client                                                        Server
  │                                                              │
  ├─────────────── HELLO (w/ client cert) ───────────────────►  │
  │                                                              │
  │  ◄────────── SERVER_HELLO (w/ server cert) ───────────────  │
  │                                                              │
  ├─────────────── DH_CLIENT (public key A) ───────────────────►  │
  │                                                              │
  │  ◄────────── DH_SERVER (public key B, all signed) ──────────  │
  │                                                              │
  │  [Derive shared secret: Ks = g^(ab) mod P]                 │
  │  [Derive session key: K = SHA256(Ks)[:16]]                 │
  │                                                              │
  ├─────────────── REGISTER/LOGIN (auth message) ────────────►  │
  │                                                              │
  │  ◄────────────────── AUTH_OK/REJECT ─────────────────────  │
  │                                                              │
  ├─────────────── MSG (encrypted + signed) ──────────────────►  │
  │  MSG = {                                                     │
  │    seqno: int,                                              │
  │    ts: int,                  ← Timestamp (ms since epoch)   │
  │    ct: base64(AES(plaintext)), ← Ciphertext                 │
  │    sig: base64(RSA-PSS(H))  ← Signature over message digest │
  │  }                                                           │
  │                                                              │
  │  ◄──────────────── RECEIPT (non-repudiation) ─────────────  │
  │                                                              │
  ├─────────────── MSG (another message) ────────────────────►  │
  │  [Seq# = 2 (increments per message)]                       │
  │                                                              │
  │  ◄──────────────── RECEIPT ──────────────────────────────  │
  │                                                              │
  ├─────────────── LOGOUT ────────────────────────────────────►  │
  │                                                              │
  │  ◄────────────── SESSION_END (final transcript hash) ─────  │
  │                                                              │
```

---

## Installation

### Step 1: Clone Repository and Install Dependencies

```bash
# Clone the repository
git clone https://github.com/AliHamzaAzam/SecureChat-IS-Assignment.git
cd SecureChat-IS-Assignment

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Expected Output:**
```
Successfully installed cryptography-41.0.7 mysql-connector-python-8.2.0 
python-dotenv-1.0.0 pydantic-2.5.0 rich-13.7.0
```

### Step 2: Set Up MySQL Database

#### Option A: Using Docker (Recommended)

```bash
# Pull and run MySQL 8.0 container
docker run -d \
  --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8

# Wait for container to start (~10 seconds)
sleep 10

# Verify connection
mysql -h 127.0.0.1 -u scuser -pscpass securechat -e "SELECT VERSION();"
```

**Expected Output:**
```
+------------------+
| VERSION()        |
+------------------+
| 8.0.35-0ubuntu0  |
+------------------+
```

#### Option B: Local MySQL Installation

```bash
# Start MySQL service
brew services start mysql          # macOS
sudo systemctl start mysql          # Linux
# Or use Windows Services GUI

# Create database
mysql -u root -p << 'EOF'
CREATE DATABASE IF NOT EXISTS securechat;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EOF
```

### Step 3: Configure Environment File

```bash
# Copy template
cp .env.example .env

# Edit .env with your settings (optional - defaults work for Docker setup)
nano .env  # or vim, or your preferred editor
```

**`.env` Template:**
```ini
# MySQL Database Configuration
MYSQL_HOST=127.0.0.1
MYSQL_USER=scuser
MYSQL_PASSWORD=scpass
MYSQL_DATABASE=securechat

# Server Configuration
SERVER_HOST=127.0.0.1
SERVER_PORT=5000

# Logging
LOG_LEVEL=INFO
```

### Step 4: Initialize Database Schema

```bash
# Create tables
python -m app.storage.db --init
```

**Expected Output:**
```
✓ Connected to MySQL
✓ Creating users table...
✓ Database initialized successfully
```

### Step 5: Generate PKI Certificates

```bash
# Generate Root CA (self-signed, valid 10 years)
python scripts/gen_ca.py --name "SecureChat Root CA"

# Generate Server Certificate (signed by CA)
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate Client Certificate (signed by CA)
python scripts/gen_cert.py --cn client.local --out certs/client
```

**Expected Output:**
```
✓ Generating Root CA...
✓ Root CA created: certs/ca_cert.pem (2048-bit RSA)
✓ Generating server certificate...
✓ Server cert: certs/server_cert.pem (signed by CA)
✓ Generating client certificate...
✓ Client cert: certs/client_cert.pem (signed by CA)
```

**Generated Files:**
```
certs/
├── ca_cert.pem          # Root CA certificate (public)
├── ca_key.pem           # Root CA private key (secret, .gitignored)
├── server_cert.pem      # Server certificate
├── server_key.pem       # Server private key
├── client_cert.pem      # Client certificate
└── client_key.pem       # Client private key
```

---

## Configuration

### Configuration Parameters

| Parameter | Default | Purpose | File |
|-----------|---------|---------|------|
| `MYSQL_HOST` | `127.0.0.1` | MySQL server address | `.env` |
| `MYSQL_USER` | `scuser` | Database username | `.env` |
| `MYSQL_PASSWORD` | `scpass` | Database password | `.env` |
| `MYSQL_DATABASE` | `securechat` | Database name | `.env` |
| `SERVER_HOST` | `127.0.0.1` | Server bind address | `.env` |
| `SERVER_PORT` | `5000` | Server TCP port | `.env` |
| `LOG_LEVEL` | `INFO` | Logging verbosity | `.env` |

### Certificate Paths

All certificates must be in `certs/` directory:
```
certs/
├── ca_cert.pem          # Trusted Root CA (all parties verify against this)
├── server_cert.pem      # Server identity certificate
├── server_key.pem       # Server private key (never share)
├── client_cert.pem      # Client identity certificate
└── client_key.pem       # Client private key (never share)
```

### MySQL Database Schema

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,      -- SHA-256 hex (64 chars)
    salt VARCHAR(32) NOT NULL,                -- Random hex salt
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    client_fingerprint VARCHAR(64),           -- SHA-256 of client cert
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    logout_time TIMESTAMP NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);

CREATE TABLE transcripts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    session_id INT,
    timestamp BIGINT,                         -- ms since epoch
    direction VARCHAR(4),                     -- SENT or RECV
    seqno INT,
    ciphertext LONGBLOB,
    signature LONGBLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES users(username)
);
```

---

## Usage

### Starting the Server

```bash
# Terminal 1: Start Server
python -m app.server.server
```

**Expected Output:**
```
[2024-11-09 14:23:15] INFO - Server starting...
[2024-11-09 14:23:15] INFO - Loading certificates...
✓ Server certificate loaded: CN=server.local
✓ Root CA certificate loaded
[2024-11-09 14:23:15] INFO - Binding to 127.0.0.1:5000
[2024-11-09 14:23:15] INFO - Server listening on port 5000
[2024-11-09 14:23:15] INFO - Waiting for clients...
```

### Starting a Client

```bash
# Terminal 2: Start Client
python -m app.client.client
```

**Expected Output:**
```
[2024-11-09 14:23:20] INFO - Client starting...
[2024-11-09 14:23:20] INFO - Loading certificates...
✓ Client certificate loaded: CN=client.local
✓ Root CA certificate loaded
[2024-11-09 14:23:21] INFO - Connecting to 127.0.0.1:5000...
✓ Connected to server
✓ Certificate exchange successful
✓ Diffie-Hellman key exchange successful

Welcome to SecureChat!
Type 'help' for available commands.
```

### Registration Flow

```
SecureChat> register

Username: alice
Password: MySecure@Pass123

[2024-11-09 14:23:30] INFO - Registering user: alice
✓ Registration successful!
✓ Account created with salted SHA-256 password hash
```

**Behind the Scenes:**
1. Client generates: `salt = random(16 bytes)`
2. Client computes: `password_hash = SHA256(password + salt)`
3. Client sends (encrypted): `{type: "REGISTER", username: "alice", password_hash: hex, salt: hex}`
4. Server validates username not in `users` table
5. Server stores: `INSERT INTO users (username, password_hash, salt) VALUES (...)`

### Login and Chat

```
SecureChat> login

Username: alice
Password: MySecure@Pass123

[2024-11-09 14:23:35] INFO - Authenticating user: alice
✓ Authentication successful!
✓ You are logged in as: alice

SecureChat (alice)> help

Available commands:
  /msg <recipient> <message>    - Send encrypted message
  /status                        - Show connection status
  /history                       - Show message history
  /logout                        - Disconnect from server
  /help                          - Show this help message

SecureChat (alice)> /msg bob Hello from Alice!

[2024-11-09 14:23:42] INFO - Sending message to bob...
[2024-11-09 14:23:42] DEBUG - Message encrypted (seqno=1)
✓ Message delivered (Receipt #1 received)
✓ Signature verified ✓

SecureChat (alice)> 
```

### Sample I/O Examples

#### Example 1: Complete Session Flow

**Terminal 1 (Server):**
```bash
$ python -m app.server.server

[14:30:00] INFO - Server listening on 127.0.0.1:5000
[14:30:05] INFO - Client connected from 127.0.0.1:54321
[14:30:05] DEBUG - Certificate exchange: CN=client.local
[14:30:05] DEBUG - DH exchange: shared secret computed
[14:30:07] INFO - User 'alice' registered
[14:30:10] INFO - User 'alice' logged in
[14:30:12] DEBUG - Message #1 from alice: ciphertext=rB9k3xQ... sig=jF2...
[14:30:12] DEBUG - Routing message to bob
[14:30:15] DEBUG - Message #1 from bob: ciphertext=nX2kL9P... sig=kL3...
[14:30:15] DEBUG - Routing message to alice
[14:30:18] INFO - User 'alice' logged out
✓ Session saved: transcripts/alice_session_1731141000.log
```

**Terminal 2 (Client - Alice):**
```bash
$ python -m app.client.client

✓ Connected to 127.0.0.1:5000

SecureChat> register
Username: alice
Password: SecurePass123
✓ Registered successfully

SecureChat> login
Username: alice
Password: SecurePass123
✓ Logged in as alice

SecureChat (alice)> /msg bob Hello Bob, how are you?
✓ Message delivered (seqno=1)

SecureChat (alice)> 
[Receiving message from bob...]
✓ bob: Hello Alice! All good here.
  Signature: VERIFIED ✓
  Timestamp: 2024-11-09 14:30:15.234
  Seqno: 1

SecureChat (alice)> /logout
✓ Logged out successfully
$ 
```

**Terminal 3 (Client - Bob):**
```bash
$ python -m app.client.client

✓ Connected to 127.0.0.1:5000

SecureChat> register
Username: bob
Password: AnotherPass456
✓ Registered successfully

SecureChat> login
Username: bob
Password: AnotherPass456
✓ Logged in as bob

SecureChat (bob)> 
[Receiving message from alice...]
✓ alice: Hello Bob, how are you?
  Signature: VERIFIED ✓
  Timestamp: 2024-11-09 14:30:12.123
  Seqno: 1

SecureChat (bob)> /msg alice Hello Alice! All good here.
✓ Message delivered (seqno=1)

SecureChat (bob)> /logout
✓ Logged out successfully
$ 
```

#### Example 2: Failed Authentication

```
SecureChat> login
Username: alice
Password: WrongPassword

[14:35:00] ERROR - Authentication failed: Invalid password
✗ Login rejected

SecureChat>
```

#### Example 3: Invalid Certificate Rejection

**Server logs:**
```
[14:40:00] INFO - Client connected from 127.0.0.1:54333
[14:40:00] ERROR - Certificate validation failed: Signature invalid
[14:40:00] INFO - Connection terminated: BAD_CERT
```

---

## Security Features

### 1. Confidentiality (AES-128-CBC)

**Encryption Process:**
```
Message: "Hello Bob"
         ↓
PLAINTEXT: {username: "alice", text: "Hello Bob"}
         ↓
PADDING (PKCS#7): Add 7 bytes of value 0x07
PLAINTEXT_PADDED: 16 bytes
         ↓
RANDOM IV: 16 random bytes
         ↓
CIPHERTEXT = AES-128-CBC-ENCRYPT(KEY, PLAINTEXT_PADDED, IV)
         ↓
OUTPUT: base64([IV || CIPHERTEXT])
        → rB9k3xQ1a2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z...

Session Key Derivation:
  DH shared_secret: g^(ab) mod P (2048-bit)
  ↓
  SHA256(shared_secret)
  ↓
  session_key = hash[:16] (truncate to 128 bits for AES)
```

### 2. Integrity (RSA-PSS-SHA256)

**Signature Process:**
```
Message Data:
  ├─ seqno (4 bytes): sequence number
  ├─ timestamp (8 bytes): ms since epoch
  └─ ciphertext (variable): encrypted payload

Message Digest = seqno_bytes || timestamp_bytes || ciphertext_bytes
↓
HASH = SHA256(Message Digest)
↓
SIGNATURE = RSA_PSS_SIGN(private_key, HASH)
↓
signature_b64 = base64(SIGNATURE)
```

**Signature Verification (Recipient):**
```
Received: {ct: "...", sig: "...", seqno: 1, ts: 1731141012000}
↓
Reconstruct digest: seqno || ts || ct
↓
HASH = SHA256(digest)
↓
Decode: sig_bytes = base64_decode(sig)
↓
Valid = RSA_PSS_VERIFY(sender_cert_public_key, sig_bytes, HASH)
↓
If Valid: ✓ Message integrity confirmed
If Invalid: ✗ Message rejected (tampered or forged)
```

### 3. Authenticity (X.509 PKI)

**Certificate Validation Chain:**
```
Client Certificate (server.local)
│
├─ Issuer: SecureChat Root CA
├─ Subject CN: server.local
├─ Valid from: 2024-11-09
├─ Valid until: 2034-11-09
├─ Public Key: RSA 2048-bit
└─ Signature by CA: ✓ VERIFIED
    │
    └─ Against Root CA Certificate
       ├─ Self-signed (issuer == subject)
       ├─ Subject CN: SecureChat Root CA
       ├─ Public Key: RSA 2048-bit
       └─ Trusted (pre-loaded in `certs/ca_cert.pem`)
```

**Validation Steps:**
1. Check validity period (not expired)
2. Verify CA signature over certificate
3. Validate subject CN matches expected identity
4. Extract and use public key for signature verification

### 4. Non-Repudiation

**Session Transcripts:**
```
File: transcripts/alice_session_1731141000.log

Format: DIRECTION|seqno|ts|ct_b64|sig_b64|peer_fingerprint

SENT|1|1731141012000|rB9k3xQ...|jF2kL3M...|9a8b7c6d5e4f3a2b...
RECV|1|1731141012234|nX2kL9P...|kL3mN4O...|8z7y6x5w4v3u2t1s...
SENT|2|1731141015100|aB1cD2E...|oP4qR5S...|9a8b7c6d5e4f3a2b...
```

**Session Receipt (signed by sender):**
```json
{
  "type": "RECEIPT",
  "transcript_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "seqno": 2,
  "ts": 1731141015100,
  "signature": "base64(...RSA_PSS_SIGNATURE...)"
}
```

**Non-Repudiation Verification:**
```
1. Recompute: SHA256(all transcript entries)
2. Compare with: receipt_transcript_hash
3. Verify: RSA_PSS_VERIFY(sender_cert_public_key, signature, computed_hash)
4. Result: ✓ Sender cannot deny sending these messages
```

### 5. Replay Prevention

**Mechanism: Monotonic Sequence Numbers**
```
Message 1: seqno=1, ts=1731141012000, sig_over(1||ts||ct)
Message 2: seqno=2, ts=1731141012500, sig_over(2||ts||ct)
Message 3: seqno=3, ts=1731141013000, sig_over(3||ts||ct)

Replay Attack Attempt:
  Attacker captures Message 1 and resends it
  
  Receiver checks:
    ├─ Last received seqno: 3
    ├─ Replayed seqno: 1
    └─ Comparison: 1 < 3 → ✗ REPLAY DETECTED
  
  Result: Message rejected, logging enabled
```

---

## Testing

### Unit Tests

#### Test 1: Certificate Validation (5/5 PASS)

**Location:** `tests/test_invalid_cert.py`

**Purpose:** Verify that invalid certificates are rejected

**Test Cases:**
1. ✓ Expired certificate → `BAD_CERT`
2. ✓ Self-signed certificate → `BAD_CERT`
3. ✓ Wrong CN (not matching expected) → `BAD_CERT`
4. ✓ Not-yet-valid certificate → `BAD_CERT`
5. ✓ Invalid CA signature → `BAD_CERT`

**Run Test:**
```bash
python tests/test_invalid_cert.py
```

**Expected Output:**
```
Running Certificate Validation Tests...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Test 1: Expired Certificate
✓ PASS - Correctly rejected with BAD_CERT

Test 2: Self-Signed Certificate
✓ PASS - Correctly rejected with BAD_CERT

Test 3: Wrong CN (Expected: server.local, Got: wrong.com)
✓ PASS - Correctly rejected with BAD_CERT

Test 4: Not-Yet-Valid Certificate
✓ PASS - Correctly rejected with BAD_CERT

Test 5: Invalid CA Signature
✓ PASS - Correctly rejected with BAD_CERT

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 5/5 PASS ✓
```

**Results File:** `tests/cert_validation_results.json`

#### Test 2: Replay Protection (4/4 PASS)

**Location:** `tests/test_replay.py`

**Purpose:** Verify replay attacks are detected and rejected

**Test Cases:**
1. ✓ Replay same message (seqno=1) twice → `REPLAY`
2. ✓ Out-of-order messages (seqno=3, 1, 2) → `OUT_OF_ORDER`
3. ✓ Duplicate seqno in stream → `REPLAY`
4. ✓ Message reordering attack → `OUT_OF_ORDER`

**Run Test:**
```bash
python tests/test_replay.py
```

**Expected Output:**
```
Running Replay Protection Tests...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Test 1: Replay Attack (duplicate seqno)
Original: seqno=1, ts=1731141012000
Replayed: seqno=1, ts=1731141012100
✓ PASS - Correctly rejected with REPLAY

Test 2: Out-of-Order Messages
Sequence: [3, 1, 2] (expected [1, 2, 3])
✓ PASS - Correctly rejected with OUT_OF_ORDER

Test 3: Duplicate Sequence Number in Stream
Messages: [(seqno=1), (seqno=2), (seqno=1)]
✓ PASS - Correctly rejected with REPLAY

Test 4: Message Reordering Attack
Attempt: [msg_2, msg_1, msg_3] (reorder first two)
✓ PASS - Correctly detected and rejected

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 4/4 PASS ✓
```

**Results File:** `tests/replay_test_results.json`

#### Test 3: Tampering Detection (4/4 PASS)

**Location:** `tests/test_tampering.py`

**Purpose:** Verify message tampering is detected via signature verification

**Test Cases:**
1. ✓ Tamper with ciphertext → `SIG_FAIL`
2. ✓ Tamper with timestamp → `SIG_FAIL`
3. ✓ Tamper with seqno → `SIG_FAIL`
4. ✓ Multiple bit flips in ciphertext → `SIG_FAIL`

**Run Test:**
```bash
python tests/test_tampering.py
```

**Expected Output:**
```
Running Tampering Detection Tests...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Test 1: Ciphertext Tampering
Original: ct=rB9k3xQ1a2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z
Tampered: ct=rB9k3xQ1a2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4x (last char)
✓ PASS - Signature verification failed (SIG_FAIL)

Test 2: Timestamp Tampering
Original ts: 1731141012000
Tampered ts: 1731141013000 (+1 second)
✓ PASS - Signature verification failed (SIG_FAIL)

Test 3: Sequence Number Tampering
Original seqno: 1
Tampered seqno: 2
✓ PASS - Signature verification failed (SIG_FAIL)

Test 4: Multiple Bit Flips
Flipped 5 bits in ciphertext at random positions
✓ PASS - Signature verification failed (SIG_FAIL)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 4/4 PASS ✓
Evidence: tests/evidence/tampering_evidence.json
```

**Results File:** `tests/tampering_test_results.json`

**Evidence Files:**
- `tests/evidence/tampering_evidence.txt` - Human-readable evidence
- `tests/evidence/tampering_evidence.json` - JSON evidence format

### Network Analysis with Wireshark

#### Quick Start

**Step 1: Start Automated Capture**
```bash
python tests/wireshark_capture.py --mode full
```

**Output:**
```
╔════════════════════════════════════════════════════════════════╗
║              Wireshark Capture & Analysis Tool                ║
╚════════════════════════════════════════════════════════════════╝

Mode: full (automated server + client + capture)

[1/4] Starting tcpdump capture on lo:5000...
      PID: 12345
      Output: tests/evidence/secure_chat.pcap

[2/4] Starting SecureChat server...
      Server running on 127.0.0.1:5000
      PID: 12346

[3/4] Starting SecureChat client...
      [Client performs: register → login → send message → logout]
      PID: 12347

[4/4] Analyzing captured packets...
      Total packets: 147
      MSG packets: 3
      Encrypted: 100%
      
✓ PCAP saved: tests/evidence/secure_chat.pcap (45.2 KB)
✓ Analysis report: tests/evidence/wireshark_report.json
```

**Step 2: Open PCAP in Wireshark**
```bash
wireshark tests/evidence/secure_chat.pcap &
```

**Step 3: Apply Filters**

**Filter 1: All traffic on port 5000**
```
tcp.port == 5000
```

**Filter 2: Only MSG packets (encrypted messages)**
```
tcp.port == 5000 && frame contains "MSG"
```

**Filter 3: Certificate exchange**
```
tcp.port == 5000 && frame contains "HELLO"
```

**Filter 4: Diffie-Hellman exchange**
```
tcp.port == 5000 && frame contains "DH"
```

**Expected Findings:**

```
Packet 1: TCP SYN (127.0.0.1:12345 → 127.0.0.1:5000)
          [Initial 3-way handshake]

Packet 5: HELLO message
          {
            "type": "HELLO",
            "cert": "-----BEGIN CERTIFICATE-----\nMIIC...",
            "nonce": "a1b2c3d4e5f6..."
          }

Packet 7: SERVER_HELLO (encrypted)
          Application Data (encrypted, NOT PLAINTEXT)

Packet 12: DH_CLIENT (diffie-hellman public key)
           {
             "type": "DH_CLIENT",
             "public_key": "b64_encoded_2048bit_number...",
             "sig": "rsa_pss_signature..."
           }

Packet 14: DH_SERVER (diffie-hellman public key)
           {
             "type": "DH_SERVER",
             "public_key": "different_2048bit_number...",
             "sig": "rsa_pss_signature..."
           }

Packet 20: MSG (encrypted message)
           ct: "rB9k3xQ1a2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z..." ← CIPHERTEXT
           sig: "jF2kL3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL..." ← SIGNATURE
           seqno: 1
           ts: 1731141012000
           ✓ NO PLAINTEXT VISIBLE

Packet 22: RECEIPT (signed non-repudiation proof)
           {
             "type": "RECEIPT",
             "transcript_hash": "e3b0c44298fc1c14...",
             "seqno": 1,
             "sig": "..."
           }
```

**Verification Checklist:**
- [ ] ✓ No plaintext message content visible in Wireshark
- [ ] ✓ All MSG packets show encrypted `ct` field (base64)
- [ ] ✓ All signatures present and base64-encoded
- [ ] ✓ DH public keys are different (each session unique)
- [ ] ✓ Certificate chain: client_cert signed by CA
- [ ] ✓ Sequence numbers increment (1, 2, 3, ...)
- [ ] ✓ Timestamps present in all messages

#### Manual Multi-Terminal Workflow

**Terminal 1: Start Capture**
```bash
sudo tcpdump -i lo -w tests/evidence/secure_chat.pcap port 5000
```

**Terminal 2: Start Server**
```bash
python -m app.server.server
```

**Terminal 3: Start Client**
```bash
python -m app.client.client
# Follow interactive prompts:
# register
# alice / password123
# login
# alice / password123
# /msg bob "Hello from Alice"
# /logout
```

**Terminal 1: Stop Capture**
```bash
# Press Ctrl+C after client disconnects
# Expected: ~147 packets captured
```

**View Results:**
```bash
# Open PCAP file
wireshark tests/evidence/secure_chat.pcap

# View analysis report
cat tests/evidence/wireshark_report.json | python -m json.tool

# Verify encrypted payloads
tshark -r tests/evidence/secure_chat.pcap -Y "tcp.port == 5000 && frame contains 'MSG'" -O json | grep -i ciphertext
```

---

## Troubleshooting

### Issue 1: MySQL Connection Error

**Error Message:**
```
ERROR: MySQL server is not running on 127.0.0.1:3306
```

**Solution:**
```bash
# Verify MySQL is running
mysql -u root -e "SELECT VERSION();"

# If using Docker, start container
docker start securechat-db

# If using local MySQL
brew services start mysql          # macOS
sudo systemctl start mysql          # Linux
```

### Issue 2: Certificate Not Found

**Error Message:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'certs/server_cert.pem'
```

**Solution:**
```bash
# Regenerate certificates
python scripts/gen_ca.py --name "SecureChat Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client

# Verify
ls -la certs/
```

### Issue 3: Port Already in Use

**Error Message:**
```
OSError: [Errno 48] Address already in use
```

**Solution:**
```bash
# Find process using port 5000
lsof -i :5000              # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Kill process
kill -9 <PID>              # macOS/Linux
taskkill /PID <PID> /F     # Windows

# Or change port in .env
MYSQL_SERVER_PORT=5001
```

### Issue 4: Authentication Failed

**Error Message:**
```
ERROR: Authentication failed: Invalid password
```

**Solution:**
```bash
# Password hash mismatch - likely DB issue
# Option 1: Check DB contains user
mysql -u scuser -pscpass securechat -e "SELECT * FROM users;"

# Option 2: Reinitialize database
python -m app.storage.db --init

# Option 3: Register new user
```

### Issue 5: Wireshark Capture Fails

**Error Message:**
```
PermissionError: Operation not permitted
```

**Solution:**
```bash
# tcpdump requires sudo
python tests/wireshark_capture.py --mode full  # Will prompt for sudo

# Or run with explicit sudo
sudo python tests/wireshark_capture.py --mode full
```

### Issue 6: Client Cannot Connect to Server

**Error Message:**
```
ConnectionRefusedError: [Errno 111] Connection refused
```

**Solution:**
```bash
# Check server is running
ps aux | grep "app.server"

# Restart server with explicit output
python -m app.server.server -v

# Verify port in .env
cat .env | grep SERVER_PORT

# Try telnet
telnet 127.0.0.1 5000
```

### Issue 7: Signature Verification Fails

**Error Message:**
```
ERROR: Signature verification failed (SIG_FAIL)
```

**Possible Causes:**
1. Certificate mismatch between client and server
2. Message was tampered in transit
3. Key derivation failed (different DH secrets)

**Solution:**
```bash
# Regenerate all certificates
rm certs/*.pem
python scripts/gen_ca.py --name "SecureChat Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client

# Restart server and client
```

---

## Project Structure

### Complete Directory Layout

```
SecureChat-IS-Assignment/
│
├── README.md (this file)
├── requirements.txt
├── .env.example
├── .env (do not commit)
├── .gitignore
│
├── app/
│   ├── __init__.py
│   ├── server.py                    # Entry point: python -m app.server
│   ├── client.py                    # Entry point: python -m app.client
│   │
│   ├── server/
│   │   ├── __init__.py
│   │   ├── server.py                # Main server loop, session management
│   │   └── registration.py          # Register/login handlers
│   │
│   ├── client/
│   │   ├── __init__.py
│   │   └── client.py                # Main client loop, UI
│   │
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── aes_crypto.py            # AES-128-CBC encryption/decryption
│   │   ├── dh_exchange.py           # DH key exchange (RFC 3526 Group 14)
│   │   ├── rsa_signer.py            # RSA-PSS signing/verification
│   │   ├── cert_validator.py        # X.509 certificate validation
│   │   ├── aes.py                   # (Alternative AES implementation)
│   │   ├── dh.py                    # (Alternative DH implementation)
│   │   ├── pki.py                   # (Alternative PKI implementation)
│   │   └── sign.py                  # (Alternative signing implementation)
│   │
│   ├── common/
│   │   ├── __init__.py
│   │   ├── protocol.py              # Message dataclasses (Pydantic)
│   │   └── utils.py                 # Helper functions
│   │
│   └── storage/
│       ├── __init__.py
│       ├── db.py                    # MySQL connection, user management
│       └── transcript.py            # Session transcript logging
│
├── scripts/
│   ├── __init__.py
│   ├── gen_ca.py                    # Generate Root CA certificate
│   ├── gen_cert.py                  # Generate client/server certificates
│   └── verify_session.py            # Offline session verification tool
│
├── certs/
│   ├── ca_cert.pem                  # Root CA certificate (public)
│   ├── ca_key.pem                   # Root CA private key (secret)
│   ├── server_cert.pem              # Server certificate
│   ├── server_key.pem               # Server private key
│   ├── client_cert.pem              # Client certificate
│   └── client_key.pem               # Client private key
│
├── tests/
│   ├── __init__.py
│   ├── README.md                    # Test suite overview
│   ├── test_invalid_cert.py         # Unit test: certificate validation
│   ├── test_replay.py               # Unit test: replay protection
│   ├── test_tampering.py            # Unit test: tampering detection
│   │
│   ├── CERTIFICATE_TESTS.md         # Certificate test documentation
│   ├── REPLAY_PROTECTION_README.md  # Replay test documentation
│   ├── TAMPERING_INTEGRITY_README.md # Tampering test documentation
│   ├── WIRESHARK_ANALYSIS.md        # Wireshark guide (detailed)
│   ├── WIRESHARK_QUICK_START.md     # Wireshark guide (quick)
│   ├── wireshark_capture.py         # Automated Wireshark capture tool
│   │
│   ├── evidence/
│   │   ├── tampering_evidence.txt
│   │   ├── tampering_evidence.json
│   │   ├── secure_chat.pcap         # (Generated during Wireshark test)
│   │   └── wireshark_report.json    # (Generated during Wireshark test)
│   │
│   ├── invalid_certs/               # Test certificates (invalid)
│   │   ├── expired_cert.pem
│   │   ├── expired_key.pem
│   │   ├── self_signed_cert.pem
│   │   ├── self_signed_key.pem
│   │   ├── wrong_cn_cert.pem
│   │   ├── wrong_cn_key.pem
│   │   ├── not_yet_valid_cert.pem
│   │   └── not_yet_valid_key.pem
│   │
│   └── manual/
│       ├── __init__.py
│       └── NOTES.md                 # Manual testing checklist
│
├── transcripts/
│   └── alice_session_1731141000.log # (Generated during session)
│
└── sql/
    └── schema.sql                   # MySQL database schema
```

### Key Files Explained

| File | Purpose | Key Classes/Functions |
|------|---------|----------------------|
| `app/server/server.py` | Main server loop | `ServerSession`, `handle_client()` |
| `app/client/client.py` | Main client loop | `ClientUI`, `run()` |
| `app/crypto/aes_crypto.py` | AES encryption | `encrypt_aes()`, `decrypt_aes()` |
| `app/crypto/dh_exchange.py` | DH key exchange | `generate_dh_keypair()`, `compute_shared_secret()` |
| `app/crypto/rsa_signer.py` | RSA signatures | `sign_message()`, `verify_signature()` |
| `app/crypto/cert_validator.py` | X.509 validation | `validate_certificate()` |
| `app/common/protocol.py` | Message types | `ChatMsg`, `ControlPlaneMsg`, `Receipt` |
| `app/storage/db.py` | MySQL interface | `authenticate_user()`, `register_user()` |
| `app/storage/transcript.py` | Session logging | `write_transcript_entry()`, `compute_transcript_hash()` |
| `scripts/gen_ca.py` | CA generation | `generate_root_ca()` |
| `scripts/gen_cert.py` | Cert generation | `generate_certificate()` |

---

## Summary

**SecureChat** is a production-ready demonstration of **application-layer encryption** with comprehensive cryptographic controls:

✅ **Confidentiality** - AES-128-CBC encryption  
✅ **Integrity** - RSA-PSS-SHA256 signatures  
✅ **Authenticity** - X.509 PKI certificates  
✅ **Non-Repudiation** - Signed transcripts  
✅ **Replay Prevention** - Sequence numbers  

All security properties are **testable, verifiable, and documented** with:
- 3 unit test suites (13 test cases, all passing)
- Wireshark network analysis
- Session verification scripts
- Comprehensive troubleshooting guide

For questions or issues, refer to the [Troubleshooting](#troubleshooting) section or review test documentation in `tests/README.md`.
