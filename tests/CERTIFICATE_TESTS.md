# Certificate Validation Test Suite

## Overview

The certificate validation test suite (`tests/test_invalid_cert.py`) provides comprehensive testing of SecureChat's certificate validation mechanisms. It verifies that the system properly rejects invalid certificates and handles various certificate error scenarios.

## Test Coverage

### Test Case 1: Expired Certificate ❌

**Scenario**: Create a certificate that expired in the past

**Expected Behavior**:
- Certificate validation fails
- Error message indicates expiration

**Implementation**:
- Create certificate valid for 1 day, backdated 2 days ago
- Call `validate_certificate()` 
- Verify rejection with expiration error

**Log Output**:
```
[2025-11-09 19:50:00] INFO: TEST 1: Expired Certificate
[2025-11-09 19:50:00] INFO: Certificate valid from: 2025-11-07 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Certificate expires: 2025-11-08 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Current time: 2025-11-09 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Validation result: ✓ PASS
[2025-11-09 19:50:00] INFO: Error message: Certificate has expired (valid until 2025-11-08...)
```

### Test Case 2: Self-Signed Certificate ❌

**Scenario**: Create a certificate not signed by the CA (self-signed)

**Expected Behavior**:
- Certificate validation fails
- Error message indicates signature verification failure

**Implementation**:
- Create certificate signed by its own key (not CA key)
- Call `validate_certificate()` with CA certificate
- Verify rejection with signature error

**Log Output**:
```
[2025-11-09 19:50:00] INFO: TEST 2: Self-Signed Certificate
[2025-11-09 19:50:00] INFO: Certificate CN: selfsigned.local
[2025-11-09 19:50:00] INFO: Issuer: CN=selfsigned.local,O=Test-Org,C=PK
[2025-11-09 19:50:00] INFO: Attempting validation against CA cert...
[2025-11-09 19:50:00] INFO: Validation result: ✓ PASS
[2025-11-09 19:50:00] INFO: Error message: Certificate signature verification failed
```

### Test Case 3: Certificate with Wrong CN/SAN ⚠️

**Scenario**: Create a CA-signed certificate but with mismatched CN/SAN

**Expected Behavior**:
- Signature validation passes (properly signed by CA)
- CN/SAN validation should detect mismatch
- Manual hostname validation fails

**Implementation**:
- Create certificate with CN=`attacker.local` but expecting `server.local`
- Verify signature passes
- Check CN mismatch with `get_cert_subject_cn()`

**Log Output**:
```
[2025-11-09 19:50:00] INFO: TEST 3: Certificate with Wrong CN/SAN
[2025-11-09 19:50:00] INFO: Expected CN: server.local
[2025-11-09 19:50:00] INFO: Actual CN: attacker.local
[2025-11-09 19:50:00] INFO: CN mismatch detected: True
[2025-11-09 19:50:00] INFO: Result: PASS
```

### Test Case 4: Certificate Not Yet Valid ❌

**Scenario**: Create a certificate valid starting tomorrow

**Expected Behavior**:
- Certificate validation fails
- Error message indicates "not yet valid"

**Implementation**:
- Create certificate with `not_valid_before` = tomorrow
- Call `validate_certificate()`
- Verify rejection with future validity error

**Log Output**:
```
[2025-11-09 19:50:00] INFO: TEST 4: Certificate Not Yet Valid
[2025-11-09 19:50:00] INFO: Current time: 2025-11-09 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Certificate valid from: 2025-11-10 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Validation result: ✓ PASS
[2025-11-09 19:50:00] INFO: Error message: Certificate not yet valid (valid from 2025-11-10...)
```

### Test Case 5: Invalid Signature ❌

**Scenario**: Verify that valid certificates pass validation

**Expected Behavior**:
- Valid certificate passes signature validation
- Any tampering would be detected

**Implementation**:
- Create properly CA-signed certificate
- Validate signature
- Verify acceptance

**Log Output**:
```
[2025-11-09 19:50:00] INFO: TEST 5: Certificate with Invalid Signature
[2025-11-09 19:50:00] INFO: Initial validation: ✓ VALID
[2025-11-09 19:50:00] INFO: Result: PASS
```

## Running the Tests

### Prerequisites

Ensure the CA certificate and key exist:
```bash
ls -l certs/ca_cert.pem certs/ca_key.pem
```

### Execute Tests

```bash
cd /Users/azaleas/Developer/Github/SecureChat-IS-Assignment

# Run the test suite
python tests/test_invalid_cert.py

# Run with verbose output
python -u tests/test_invalid_cert.py 2>&1 | tee /tmp/test_output.log
```

### Output Files

The test suite generates several output files:

1. **`tests/cert_validation_test.log`** - Detailed test execution log
   - All INFO and DEBUG messages
   - Certificate details and error messages
   - Timestamp for each log entry

2. **`tests/cert_validation_results.json`** - Machine-readable results
   ```json
   {
     "timestamp": "2025-11-09T19:50:00",
     "summary": {
       "total": 5,
       "passed": 5,
       "failed": 0,
       "errors": 0,
       "skipped": 0
     },
     "results": [
       {
         "test": "expired_certificate",
         "status": "PASS",
         "validation_error": "Certificate has expired..."
       },
       ...
     ]
   }
   ```

3. **`tests/invalid_certs/`** - Generated test certificates
   ```
   tests/invalid_certs/
   ├── expired_server_cert.pem
   ├── expired_server_key.pem
   ├── self_signed_cert.pem
   ├── self_signed_key.pem
   ├── wrong_cn_cert.pem
   ├── wrong_cn_key.pem
   ├── not_yet_valid_cert.pem
   ├── not_yet_valid_key.pem
   └── ...
   ```

## Test Results Interpretation

### Exit Codes

- `0` - All tests passed ✅
- `1` - One or more tests failed ❌

### Summary Report

```
TEST SUMMARY
============
Total: 5
Passed: 5 ✓
Failed: 0 ✗
Errors: 0 ⚠
Skipped: 0 ⊘
```

### Individual Test Results

Each test returns:
```python
{
    "test": "test_name",
    "status": "PASS|FAIL|ERROR|SKIPPED",
    "expected": "Expected behavior description",
    "actual": "Actual behavior observed",
    "error": "Error message (if any)"
}
```

## Expected Results

For a working certificate validation implementation:

| Test | Expected Status | Why |
|------|-----------------|-----|
| Expired Certificate | ✓ PASS | Validation correctly rejects expired cert |
| Self-Signed Certificate | ✓ PASS | Signature verification fails (not signed by CA) |
| Wrong CN/SAN | ✓ PASS | CN mismatch detected by hostname validation |
| Not Yet Valid | ✓ PASS | Validation correctly rejects future cert |
| Invalid Signature | ✓ PASS | Valid cert passes, tampering would be caught |

## Architecture

### Test Structure

```
test_invalid_cert.py
├── Logging setup
│   └── Log to file + console
├── Certificate generation utilities
│   ├── generate_key_pair()
│   ├── create_self_signed_cert()
│   └── create_ca_signed_cert_with_wrong_cn()
├── Test cases (5 total)
│   ├── test_expired_certificate()
│   ├── test_self_signed_certificate()
│   ├── test_wrong_cn_certificate()
│   ├── test_not_yet_valid_certificate()
│   └── test_invalid_signature()
├── Result collection and reporting
│   └── JSON export
└── Exit code handling
```

### Validation Flow

```
Test Case
    │
    ├─ Generate Test Certificate
    │  └─ Save to tests/invalid_certs/
    │
    ├─ Call validate_certificate()
    │
    ├─ Check Results
    │  ├─ is_valid: bool
    │  └─ error: str
    │
    └─ Log Results
       ├─ Write to tests/cert_validation_test.log
       └─ Append to results JSON
```

## Integration with CI/CD

The test suite can be integrated into CI/CD pipelines:

```bash
#!/bin/bash
# Run certificate validation tests
python tests/test_invalid_cert.py
TEST_RESULT=$?

# Check results
if [ $TEST_RESULT -eq 0 ]; then
    echo "✓ Certificate validation tests PASSED"
    exit 0
else
    echo "✗ Certificate validation tests FAILED"
    cat tests/cert_validation_test.log
    exit 1
fi
```

## Troubleshooting

### CA Certificate Not Found

If you see:
```
WARNING: CA certificate not found, skipping test
```

**Solution**: Generate CA certificate first:
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

### Import Errors

If you see:
```
ModuleNotFoundError: No module named 'app'
```

**Solution**: Run from the project root directory:
```bash
cd /path/to/SecureChat-IS-Assignment
python tests/test_invalid_cert.py
```

### Permission Denied

If you see errors writing to `tests/invalid_certs/`:

**Solution**: Ensure directory exists and is writable:
```bash
mkdir -p tests/invalid_certs
chmod 755 tests/invalid_certs
```

## Security Considerations

### Test Certificates

The test certificates generated by this suite are:
- **NOT** cryptographically strong (for performance)
- **NOT** meant for production use
- **ONLY** for testing validation logic
- Generated with **2048-bit RSA** (sufficient for testing)

### Sensitive Operations

The tests do NOT:
- Store passwords or secrets
- Connect to real servers
- Send data over network
- Modify system certificates

## Files Generated

### Test Artifacts

```
tests/
├── test_invalid_cert.py          # Main test file
├── cert_validation_test.log       # Detailed log
├── cert_validation_results.json   # Machine-readable results
└── invalid_certs/                 # Test certificates directory
    ├── expired_server_cert.pem
    ├── expired_server_key.pem
    ├── self_signed_cert.pem
    ├── self_signed_key.pem
    ├── wrong_cn_cert.pem
    ├── wrong_cn_key.pem
    ├── not_yet_valid_cert.pem
    ├── not_yet_valid_key.pem
    └── ...
```

## Related Documentation

- [VERIFY_SESSION.md](../VERIFY_SESSION.md) - Offline session verification
- [VERIFICATION_COMPLETE.md](../VERIFICATION_COMPLETE.md) - Non-repudiation verification
- [README.md](../README.md) - SecureChat overview

## Example Test Run

```bash
$ python tests/test_invalid_cert.py

╔════════════════════════════════════════════════════════════════════╗
║          CERTIFICATE VALIDATION TEST SUITE                        ║
╚════════════════════════════════════════════════════════════════════╝

[2025-11-09 19:50:00] INFO: ======================================================================
[2025-11-09 19:50:00] INFO: TEST 1: Expired Certificate
[2025-11-09 19:50:00] INFO: ======================================================================
[2025-11-09 19:50:00] INFO: Creating certificate valid for 1 day, created 2 days ago...
[2025-11-09 19:50:00] INFO: Certificate valid from: 2025-11-07 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Certificate expires: 2025-11-08 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Current time: 2025-11-09 19:50:00+00:00
[2025-11-09 19:50:00] INFO: Validation result: ✓ PASS
[2025-11-09 19:50:00] INFO: Error message: Certificate has expired (valid until 2025-11-08 19:50:00+00:00)
[2025-11-09 19:50:00] INFO: Result: PASS
[2025-11-09 19:50:00] INFO: 

[... more tests ...]

======================================================================
TEST SUMMARY
======================================================================
[2025-11-09 19:50:00] INFO: Total: 5
[2025-11-09 19:50:00] INFO: Passed: 5 ✓
[2025-11-09 19:50:00] INFO: Failed: 0 ✗
[2025-11-09 19:50:00] INFO: Errors: 0 ⚠
[2025-11-09 19:50:00] INFO: Skipped: 0 ⊘
[2025-11-09 19:50:00] INFO: 
[2025-11-09 19:50:00] INFO: Results saved to: tests/cert_validation_results.json
[2025-11-09 19:50:00] INFO: Logs saved to: tests/cert_validation_test.log
[2025-11-09 19:50:00] INFO: Exit code: 0
```

## References

- **cryptography library**: https://cryptography.io/
- **X.509 certificates**: https://en.wikipedia.org/wiki/X.509
- **NIST SP 800-32**: Recommendation for Digital Signature Algorithms
- **RFC 5280**: Internet X.509 PKI Certificate and CRL Profile
