# Session Verification Tool

## Overview

`scripts/verify_session.py` is an offline verification utility for SecureChat session transcripts and receipts. It validates the non-repudiation guarantees by:

1. **Verifying individual message signatures** - Ensures no message was tampered with
2. **Computing transcript hash** - SHA-256 of all transcript entries
3. **Verifying receipt signature** - Ensures receipt wasn't forged
4. **Detecting tampering** - Any modification is caught immediately

## Security Properties

The verification tool validates that:

- ✅ **Message Authenticity**: Each message signature verifies the sender identity
- ✅ **Message Integrity**: Any bit-flip in ciphertext invalidates signature
- ✅ **Transcript Integrity**: Transcript hash must match receipt's hash
- ✅ **Receipt Authenticity**: Receipt signature must verify with peer certificate
- ✅ **No Tampering**: Modifications detected at message and/or transcript level

## Usage

### Basic Usage

```bash
python scripts/verify_session.py \
    --transcript transcripts/alice_session_1762699111434.log \
    --receipt transcripts/alice_receipt_1762699111434.json \
    --cert certs/server_cert.pem
```

### Arguments

- `--transcript <path>`: Path to session transcript `.log` file
- `--receipt <path>`: Path to session receipt `.json` file  
- `--cert <path>`: Path to peer's certificate (`.pem`) for verification

### Exit Codes

- `0` - All verifications passed ✅
- `1` - Verification failed (tampering detected) ❌
- `2` - Invalid arguments or file not found ⚠️

## Output

### Successful Verification

```
======================================================================
MESSAGE SIGNATURE VERIFICATION
======================================================================
Total messages: 1
Valid signatures: 1
Invalid signatures: 0

✓ All message signatures valid

======================================================================
TRANSCRIPT & RECEIPT VERIFICATION
======================================================================
Sequence range: 1-1
Computed hash:  d556527b5884a6aad...
Receipt hash:   d556527b5884a6aad...
Hashes match:   ✓ Yes
Receipt signature: ✓ Valid

======================================================================
VERIFICATION SUMMARY
======================================================================

✓ ALL VERIFICATIONS PASSED
  - All message signatures verified
  - Transcript hash matches receipt
  - Receipt signature valid

Non-repudiation guarantees satisfied!
```

### Tampering Detected

```
======================================================================
MESSAGE SIGNATURE VERIFICATION
======================================================================
Total messages: 1
Valid signatures: 0
Invalid signatures: 1

Invalid messages:
  Line 1 (seqno=1): RSA-PSS signature verification failed

======================================================================
TRANSCRIPT & RECEIPT VERIFICATION
======================================================================
Sequence range: 1-1
Computed hash:  fc1c2127fab96c39...
Receipt hash:   d556527b5884a6aa...
Hashes match:   ✗ No
Receipt signature: ✗ Invalid

Error: Transcript hash mismatch!
  Computed: fc1c2127fab96c391a491d308c7afaafcc0710c93c63fa25b8070df849bd8c03
  Receipt:  d556527b5884a6aadc5a25ba4c870805ccae8f3a19a6a531627f2e8fc6fcca90

======================================================================
VERIFICATION SUMMARY
======================================================================

✗ VERIFICATION FAILED
  - 1 invalid message signature(s)
  - Receipt verification failed

Possible tampering detected!
```

## Implementation Details

### Message Signature Verification

Each transcript entry contains a message signature over:
```
SHA256(seqno_bytes(4) || ts_bytes(8) || ciphertext_bytes)
```

The verification process:
1. Parse transcript line: `direction|seqno|ts|ct_b64|sig_b64|fp`
2. Reconstruct digest from seqno, timestamp, and ciphertext
3. Verify RSA-PSS signature using peer certificate
4. Report result per message

### Transcript Hash Verification

1. Read all transcript lines (append-only file)
2. Compute SHA-256 of concatenated entries
3. Compare computed hash with receipt's `transcript_sha256` field
4. Verify receipt's signature over the hash

### Receipt Format

```json
{
  "type": "receipt",
  "peer": "client|server",
  "username": "alice",
  "first_seq": 1,
  "last_seq": 1,
  "transcript_sha256": "d556527b5884a6aad...",
  "sig": "BaW0gHJ3wPg67cMpz..."
}
```

- **transcript_sha256**: Hex-encoded SHA-256 of transcript
- **sig**: Base64-encoded RSA-PSS signature over hash

## Tamper Test Example

### 1. Create a valid session
```bash
# Run server in terminal 1
python -m app.server.server

# Run client in terminal 2 and send a message
python -m app.client.client
# Login and send: "hello server"
# Exit (generates receipt and transcript)
```

### 2. Verify original session works
```bash
# Find the latest transcript and receipt files
ls -t transcripts/ | head -5

# Verify (should PASS)
python scripts/verify_session.py \
    --transcript transcripts/alice_session_*.log \
    --receipt transcripts/alice_receipt_*.json \
    --cert certs/server_cert.pem
```

### 3. Tamper with transcript
```bash
# Copy transcript for testing
cp transcripts/alice_session_*.log /tmp/tampered.log

# Modify ciphertext (change one character)
# Original: 2ZbT1jmg8UqBI4p8X1Sz2MzOOl7IFAYsyu0tHTxIbBE=
# Modified: 2ZbT1jmg8UqBI4p8X1Sz2MzOOl7IFAYsyu0tXXxIbBE=
sed -i '' 's/2ZbT1jmg8UqBI4p8X1Sz2MzOOl7IFAYsyu0tHTxIbBE=/2ZbT1jmg8UqBI4p8X1Sz2MzOOl7IFAYsyu0tXXxIbBE=/' /tmp/tampered.log
```

### 4. Verify tampering is detected
```bash
# Verify (should FAIL)
python scripts/verify_session.py \
    --transcript /tmp/tampered.log \
    --receipt transcripts/alice_receipt_*.json \
    --cert certs/server_cert.pem

# Output:
# ✗ VERIFICATION FAILED
#   - 1 invalid message signature(s)
#   - Transcript hash mismatch
# Possible tampering detected!
```

## Code Structure

### Key Functions

#### `verify_message_signature(line, peer_cert_pem)`
Verifies a single transcript entry signature.

**Input**: Transcript line + peer certificate  
**Output**: (valid: bool, error: str)

#### `verify_transcript_receipt(transcript_path, receipt_path, peer_cert_pem)`
Verifies transcript integrity and receipt signature.

**Input**: Transcript file + receipt file + peer certificate  
**Output**: (valid: bool, details: dict)

**Details Dict**:
```python
{
    "transcript_hash": str,      # Computed SHA-256
    "receipt_hash": str,         # Hash from receipt
    "hash_match": bool,          # Hashes match
    "receipt_sig_valid": bool,   # Signature valid
    "first_seq": int,            # Min seqno
    "last_seq": int,             # Max seqno
    "error": str,                # Error message
}
```

#### `verify_all_messages(transcript_path, peer_cert_pem)`
Verifies all message signatures in transcript.

**Output**: Results dict with per-message verification status

### Main Flow

1. Load transcript and receipt files
2. Verify each message signature individually
3. Compute transcript hash
4. Verify receipt signature
5. Report detailed results
6. Return exit code (0=pass, 1=fail)

## Architecture Notes

### Append-Only Transcripts

Transcripts use append-only semantics:
- File opened in append mode (`'a'`)
- Each write is atomic (flush after write)
- No overwriting or deletion of entries
- Immutable audit trail

### Signature Scheme

Uses RSA-PSS with:
- **Key**: 2048-bit RSA
- **Hash**: SHA-256
- **Padding**: PSS (probabilistic, prevents forgery)
- **Salt**: SHA-256 output size (32 bytes)

### Hash Computation

Transcript hash includes:
- All SENT/RECV entries
- Full line format: `direction|seqno|ts|ct|sig|fp\n`
- SHA-256 of concatenated bytes

## Related Components

- **Transcript Writing**: `app/storage/transcript.py`
- **Receipt Generation**: `app/storage/transcript.py` (generate_session_receipt)
- **Signature Functions**: `app/crypto/rsa_signer.py`
- **Certificate Validation**: `app/crypto/cert_validator.py`

## Troubleshooting

### "No module named 'app'"
The script needs the app module in Python path. Run from workspace root:
```bash
cd /path/to/SecureChat-IS-Assignment
python scripts/verify_session.py --transcript ... --receipt ... --cert ...
```

### "Certificate not found"
Ensure certificate path is correct and readable:
```bash
ls -l certs/server_cert.pem  # or client_cert.pem
```

### "Invalid base64 signature"
The signature field in receipt may be corrupted. Check receipt JSON:
```bash
cat transcripts/alice_receipt_*.json | jq .sig
```

### "Transcript hash mismatch"
Either:
1. Transcript file was modified
2. Wrong receipt file (from different session)
3. Truncated/corrupted file

Verify files are from same session:
```bash
# Should have same timestamp
ls -l transcripts/alice_session_1762699111434.log
ls -l transcripts/alice_receipt_1762699111434.json
```

## Security Considerations

### What is Verified

✅ Message signatures (authenticity + integrity)  
✅ Transcript integrity (hash match)  
✅ Receipt signature (authenticity)  

### What is NOT Verified

- Certificate validity window (already validated at session time)
- Certificate chain (done during handshake)
- Server/client session separation
- Replay of old transcripts

### For Production

- Pin certificate fingerprints for known peers
- Verify certificate chain using CA
- Store transcripts in secure, tamper-evident medium
- Implement digital timestamping service
- Regular audit log verification

## Performance

- Signature verification: ~5-10ms per message (RSA-2048)
- Transcript hashing: O(n) where n = transcript size
- Typical session (1 message): <100ms

For large transcripts (100+ messages):
- Batch verification recommended
- Consider incremental hashing
- Off-load to dedicated verification service
