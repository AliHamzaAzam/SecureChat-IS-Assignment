# Copilot Instructions for SecureChat

## Project Overview

**SecureChat** is a console-based PKI-enabled secure chat system demonstrating cryptographic principles (Confidentiality, Integrity, Authenticity, Non-Repudiation via CIANR properties).

- **Language**: Python 3.10+
- **Architecture**: Single-threaded TCP client/server with application-layer cryptography
- **Key Constraint**: NO TLS/SSL — all crypto operations must be explicit at application layer
- **Core Stack**: RSA (authentication), DH (key exchange), AES-128-CBC (encryption), SHA-256 (hashing)

---

## Critical Architecture

### Message Flow (Application Protocol)

1. **HELLO** → Server cert + client nonce
2. **SERVER_HELLO** → Client cert + server nonce
3. **REGISTER/LOGIN** → User authentication (salted SHA-256 vs MySQL `users` table)
4. **DH_CLIENT/DH_SERVER** → RFC 3526 Group 14 (2048-bit safe prime) key exchange
5. **MSG** → AES-128-CBC encrypted messages with RSA-PSS signatures + seq#/timestamp
6. **RECEIPT** → Non-repudiation proof (signed transcript hash)

**Location**: `app/common/protocol.py` defines `ControlPlaneMsg`, `DHClientMsg`, `DHServerMsg`, `ChatMsg`, `SessionReceipt` dataclasses.

### Network Framing

**Length-prefixed format** (NOT raw JSON):
```
[4 bytes: big-endian msg length] [JSON message body]
```

All messages are JSON-serializable via `serialize_message()` / `deserialize_message()` helpers.

**Location**: `app/client/client.py` (lines ~250–300) and `app/server/server.py` handle socket I/O.

---

## Component Boundaries

| Module | Responsibility | Key Files |
|--------|-----------------|-----------|
| **Crypto Layer** | RSA signing, DH exchange, AES encryption, PKI validation | `app/crypto/{aes_crypto,dh_exchange,cert_validator,rsa_signer}.py` |
| **Protocol Layer** | Message serialization, type definitions, nonce/seq# handling | `app/common/protocol.py` + helpers in `utils.py` |
| **Storage** | MySQL user table (username/salted-SHA256-hash), session transcript | `app/storage/{db.py, transcript.py}` |
| **Client** | TCP connect, cert exchange, DH handshake, interactive chat loop | `app/client/client.py` |
| **Server** | TCP listen, client session management, message relay, auth | `app/server/server.py` |
| **PKI Setup** | Generate Root CA, issue client/server X.509 certs | `scripts/{gen_ca.py, gen_cert.py}` |

---

## Key Patterns & Conventions

### 1. **Symmetric Key Derivation**
```python
# After DH shared secret (bytes), derive 16-byte AES key:
from app.crypto.dh_exchange import compute_shared_secret
from app.common.utils import sha256_hex

shared_secret = compute_shared_secret(my_dh_private, peer_dh_public)
session_key = sha256_hex(shared_secret)[:32].encode()[:16]  # Trunc16(SHA-256)
```
**Location**: `app/crypto/dh_exchange.py` (functions `generate_dh_keypair()`, `compute_shared_secret()`)

### 2. **Message Signing (RSA-PSS)**
```python
from app.crypto.rsa_signer import sign_message, verify_signature

# Sign with private key (PEM string)
signature_b64 = sign_message(json.dumps(msg_dict), private_key_pem)

# Verify with public cert
is_valid = verify_signature(json.dumps(msg_dict), signature_b64, public_cert_pem)
```
**Location**: `app/crypto/rsa_signer.py`

### 3. **Certificate Validation (PKI)**
- Always validate cert against **CA certificate** (`certs/ca_cert.pem`)
- Check **validity window** (not before / not after)
- Verify **CN** (Common Name) matches expected identity
- **Location**: `app/crypto/cert_validator.py` — function `validate_certificate(cert, ca_cert)`

### 4. **Database Initialization**
```bash
python -m app.storage.db --init  # Creates MySQL DB & users table
```
**Schema**: `users(id INT, username VARCHAR, password_hash VARCHAR, salt VARCHAR)`
**Location**: `sql/schema.sql`

### 5. **Environment Configuration**
Loaded from `.env` via `python-dotenv`:
```
MYSQL_HOST=localhost
MYSQL_USER=scuser
MYSQL_PASSWORD=scpass
MYSQL_DATABASE=securechat
SERVER_HOST=127.0.0.1
SERVER_PORT=5000
```

---

## Common Workflows

### Setting Up Dev Environment
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Start MySQL (docker):
docker run -d --name securechat-db -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass -p 3306:3306 mysql:8
python -m app.storage.db --init
```

### Certificate Generation
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
python scripts/gen_cert.py --cn server.local --out certs/server
python scripts/gen_cert.py --cn client.local --out certs/client
```
**Files created**: `certs/{ca_cert.pem, ca_key.pem, server_cert.pem, server_key.pem, client_cert.pem, client_key.pem}`

### Running Server & Client
```bash
# Terminal 1: Start server
python -m app.server.server
# Terminal 2: Start client  
python -m app.client.client
```

### Testing
```bash
# Test certificate exchange
python test_certificate_exchange.py

# Run unit tests (if any)
pytest tests/
```

---

## Critical Implementation Details

### DH Exchange
- **Prime (P)**: RFC 3526 Group 14 (2048-bit safe prime) — hardcoded in `app/crypto/dh_exchange.py` line 44
- **Generator (G)**: 2
- **Public key validation**: Must be in range `1 < A < P - 1` — see `validate_public_key()`
- **Shared secret derivation**: `Ks = pow(peer_public, my_private, P)` → convert to bytes → `SHA256(Ks)` → take first 16 bytes for AES key

### AES Encryption
- **Mode**: CBC (Cipher Block Chaining)
- **IV**: Random 16 bytes prepended to ciphertext (NOT shared)
- **Padding**: PKCS#7 (automatic via `cryptography` library)
- **Output format**: `[16-byte IV] + [encrypted data]` (base64-encoded for JSON)

### Session Non-Repudiation
- Each message includes **sequence number** (increments per message) and **timestamp** (ms since epoch)
- Session receipt contains **hash of transcript** signed by sender (proves message sequence integrity)
- **Location**: `app/storage/transcript.py` — `compute_transcript_hash()`

### Error Handling
- Network errors → log and gracefully close connection
- Protocol errors (invalid JSON, bad nonce) → send error message, terminate session
- Crypto errors (invalid signature, cert validation fail) → reject message, log security event
- **Logging**: All components use Python `logging` module; see server/client startup for configuration

---

## Code Style & Imports

- **Module imports**: Use absolute imports from `app.*` when possible
- **Type hints**: Required for function signatures (Python 3.10+ style)
- **Docstrings**: Module, class, and function docstrings required (Google style)
- **Pydantic models**: Use for message validation where applicable (see `protocol.py` for examples)
- **Secrets**: Never log passwords, private keys, or session keys — use string masking if logging sensitive ops

---

## Debugging Tips

1. **Enable verbose logging**: Set `logging.basicConfig(level=logging.DEBUG)` in entry points
2. **Inspect network traffic**: Use Wireshark to capture TCP packets and verify message framing
3. **Replay attack tests**: Capture a MSG and resend with same seq# — should be rejected
4. **Tamper detection**: Modify a signature bit in captured message — verification should fail
5. **Certificate pinning**: Add fingerprint checks in `cert_validator.py` for production hardening

---

## References

- **Cryptography library**: https://cryptography.io/
- **Pydantic**: https://docs.pydantic.dev/
- **MySQL Connector**: https://dev.mysql.com/doc/connector-python/en/
- **RFC 3526**: Diffie-Hellman Group 14 parameters
- **PKCS#7 Padding**: RFC 5652 Section 6.3
