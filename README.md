
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

This repository is the **official code skeleton** for your Assignment #2.  
You will build a **console-based, PKI-enabled Secure Chat System** in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.


## 🧩 Overview

You are provided only with the **project skeleton and file hierarchy**.  
Each file contains docstrings and `TODO` markers describing what to implement.

Your task is to:
- Implement the **application-layer protocol**.
- Integrate cryptographic primitives correctly to satisfy the assignment spec.
- Produce evidence of security properties via Wireshark, replay/tamper tests, and signed session receipts.

## 🏗️ Folder Structure
```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/manual/NOTES.md     # Manual testing + Wireshark evidence checklist
├─ certs/.keep               # Local certs/keys (gitignored)
├─ transcripts/.keep         # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Minimal dependencies
└─ .github/workflows/ci.yml  # Compile-only sanity check (no execution)
```

## ⚙️ Setup Instructions

1. **Fork this repository** to your own GitHub account(using official nu email).  
   All development and commits must be performed in your fork.

2. **Set up environment**:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   cp .env.example .env
   ```

3. **Initialize MySQL** (recommended via Docker):
   ```bash
   docker run -d --name securechat-db        -e MYSQL_ROOT_PASSWORD=rootpass        -e MYSQL_DATABASE=securechat        -e MYSQL_USER=scuser        -e MYSQL_PASSWORD=scpass        -p 3306:3306 mysql:8
   ```

4. **Create tables**:
   ```bash
   python -m app.storage.db --init
   ```

5. **Generate certificates** (after implementing the scripts):
   ```bash
   python scripts/gen_ca.py --name "FAST-NU Root CA"
   python scripts/gen_cert.py --cn server.local --out certs/server
   python scripts/gen_cert.py --cn client.local --out certs/client
   ```

6. **Run components** (after implementation):
   ```bash
   python -m app.server
   # in another terminal:
   python -m app.client
   ```

## 🚫 Important Rules

- **Do not use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- You are **not required** to implement AES, RSA, or DH math, Use any of the available libraries.
- Do **not commit secrets** (certs, private keys, salts, `.env` values).
- Your commits must reflect progressive development — at least **10 meaningful commits**.

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. A ZIP of your **GitHub fork** (repository).
2. MySQL schema dump and a few sample records.
3. Updated **README.md** explaining setup, usage, and test outputs.
4. `RollNumber-FullName-Report-A02.docx`
5. `RollNumber-FullName-TestReport-A02.docx`

## 📋 Usage Guide

### Starting the Server
```bash
python -m app.server
```
The server listens on the configured `SERVER_HOST` and `SERVER_PORT` (default: localhost:9999).

### Starting a Client
```bash
python -m app.client
```
The client connects to the server and provides an interactive console for sending messages.

### Database Initialization
```bash
python -m app.storage.db --init
```
This creates the necessary tables in MySQL and initializes the database schema.

## 🔐 Security Features Implemented

- **Confidentiality**: AES-128 ECB mode with PKCS#7 padding
- **Integrity**: HMAC verification of all messages
- **Authenticity**: RSA signatures with SHA-256
- **Non-Repudiation**: Signed session receipts and append-only transcript
- **Key Exchange**: Diffie-Hellman key agreement
- **Certificate Validation**: X.509 PKI with Root CA signature verification

## 🧪 Testing

### Manual Testing
See `tests/manual/NOTES.md` for detailed manual testing procedures.

### Wireshark Analysis
1. Start tcpdump or Wireshark to capture traffic on localhost:9999
2. Run server and client
3. Verify that payloads are encrypted and only metadata is visible

### Test Evidence Checklist

✔ **Wireshark capture** - Encrypted payloads only  
✔ **Invalid cert rejection** - `BAD_CERT` status for self-signed certificates  
✔ **Tamper test** - Signature verification fails (`SIG_FAIL`)  
✔ **Replay protection** - Rejected by sequence number (`REPLAY`)  
✔ **Non-repudiation** - Exported transcript + signed SessionReceipt verified offline

## 📝 Project Structure Details

### Crypto Modules
- **`aes.py`**: Encryption/decryption with AES-128-ECB and PKCS#7
- **`dh.py`**: Diffie-Hellman prime generation and key derivation
- **`pki.py`**: X.509 certificate validation against Root CA
- **`sign.py`**: RSA-2048 signature generation and verification

### Application Layer
- **`protocol.py`**: Pydantic models for all message types
- **`utils.py`**: Base64 encoding, timestamping, SHA-256 hashing
- **`client.py`**: Client-side protocol handler and UI
- **`server.py`**: Server-side session management and message routing

### Storage
- **`db.py`**: MySQL connection pooling and user management
- **`transcript.py`**: Immutable session logs with cryptographic verification

### Scripts
- **`gen_ca.py`**: Root CA certificate generation (self-signed X.509)
- **`gen_cert.py`**: Client and server certificate issuance signed by Root CA

## 🛠️ Development Notes

- All cryptographic operations use the `cryptography` library
- MySQL user accounts store salted SHA-256 password hashes
- Transcripts are append-only and include sequence numbers
- All messages include timestamps (milliseconds since epoch)
- Certificates are stored in `certs/` directory (not committed to git)
