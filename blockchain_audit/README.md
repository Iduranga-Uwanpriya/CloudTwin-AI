# 🔐 Blockchain Audit Module

## Overview

Tamper-proof compliance logging system using blockchain technology.

## Features

- **SHA-256 Hash Chain**: Each block cryptographically linked to previous
- **Immutable Records**: Audit logs cannot be altered without detection
- **Integrity Verification**: Verify entire chain hasn't been tampered with
- **Timestamp Tracking**: Every compliance check timestamped
- **Genesis Block**: Initial block establishes chain

## How It Works

### 1. Hash Chain
Each block contains:
- Block ID
- Timestamp
- Compliance data
- Previous block hash
- Current block hash (calculated from all above)

### 2. Adding Logs
```python
from blockchain_audit.hash_chain import blockchain_logger

blockchain_logger.add_compliance_log(
    resource_name="my-bucket",
    resource_type="s3_bucket",
    compliance_score=85.5,
    checks_passed=3,
    checks_total=4,
    check_details={...}
)
```

### 3. Retrieving Audit Trail
```python
# Get all logs
trail = blockchain_logger.get_audit_trail()

# Get logs for specific resource
trail = blockchain_logger.get_audit_trail(resource_name="my-bucket")

# Get last 10 logs
trail = blockchain_logger.get_audit_trail(limit=10)
```

### 4. Verify Integrity
```python
is_valid, error = blockchain_logger.verify_chain_integrity()
if is_valid:
    print("✅ Blockchain is valid")
else:
    print(f"❌ Blockchain tampered: {error}")
```

## Storage

Logs stored in: `blockchain_audit/audit_logs.json`

## Security

- **Immutability**: Changing any block invalidates all subsequent blocks
- **Cryptographic Security**: SHA-256 hashing
- **Chain Verification**: Detects any tampering attempts
- **Timestamp Proof**: Proves when each audit occurred

## Use Cases

1. **Compliance Auditing**: Prove compliance checks weren't altered
2. **Forensic Analysis**: Track compliance changes over time
3. **Regulatory Reporting**: Verifiable audit trail for regulators
4. **Incident Response**: Investigate security incidents with tamper-proof logs

## Future Enhancements

- Multi-node blockchain (distributed)
- Digital signatures
- Merkle tree optimization
- Smart contracts for automated remediation