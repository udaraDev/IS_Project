# IS Project — Implementation Plan

## Zero Trust Secure Communication Framework for Malware Sample Submission

> **Deadline:** Evaluation week starting 18th May 2026
> **Link to FYP:** This secures the binary submission pipeline of your malware static analysis project. When a user submits a PE binary for analysis, this framework ensures the transfer is authenticated, encrypted, integrity-verified, and quantum-resistant.

---

## 1. System Architecture

```
┌──────────────────┐                              ┌──────────────────────┐
│   CLIENT (User)  │                              │  SERVER (Analyzer)   │
│                  │                              │                      │
│ 1. Load PE binary│    ── Mutual TLS (mTLS) ──>  │ 1. Verify client cert│
│ 2. Generate AES  │    ── Kyber KEM ──────────>  │ 2. Decapsulate key   │
│    session key   │                              │ 3. Derive AES key    │
│ 3. Encrypt binary│    ── Encrypted Payload ──>  │ 4. Decrypt binary    │
│    (AES-256-GCM) │                              │ 5. Verify HMAC       │
│ 4. Sign HMAC     │    ── HMAC-SHA256 ───────>   │ 6. Run decompiler    │
│                  │                              │    pipeline (FYP)    │
│                  │    <── Analysis Result ────   │ 7. Return results    │
└──────────────────┘                              └──────────────────────┘
```

---

## 2. Security Properties & How They're Achieved

| Property | Technique | Implementation |
|----------|-----------|----------------|
| **Confidentiality** | AES-256-GCM encryption | Binary payload encrypted with 256-bit symmetric key |
| **Integrity** | HMAC-SHA256 | Message authentication code over encrypted payload |
| **Authentication** | Mutual TLS (mTLS) | Both client and server present X.509 certificates |
| **Non-repudiation** | Digital signatures (RSA-2048) | Client signs submission; server signs results |
| **Post-Quantum Readiness** | Kyber-768 KEM | Hybrid key exchange: classical ECDH + Kyber lattice-based |
| **Zero Trust** | Never trust, always verify | Every request re-authenticated; no session persistence |

---

## 3. Implementation Components

### Component 1: Certificate Authority (CA) & Mutual TLS

**What:** Create a self-signed root CA, issue client + server certificates.

```
certs/
├── ca.key              # Root CA private key
├── ca.crt              # Root CA certificate
├── server.key          # Server private key
├── server.crt          # Server certificate (signed by CA)
├── client.key          # Client private key
└── client.crt          # Client certificate (signed by CA)
```

**Generate (OpenSSL commands):**
```bash
# 1. Create CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 365 -out ca.crt -subj "/CN=MalwareAnalysisCA"

# 2. Server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=analysis-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# 3. Client cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=analyst-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### Component 2: Key Exchange (Hybrid Classical + Post-Quantum)

**What:** Use ECDH for classical key agreement + Kyber-768 for PQ key encapsulation. Combine both to derive the final AES session key.

```python
# pip install pqcrypto  (or oqs-python for liboqs bindings)
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def hybrid_key_exchange():
    # Classical: ECDH (P-256)
    client_ecdh = ec.generate_private_key(ec.SECP256R1())
    server_ecdh = ec.generate_private_key(ec.SECP256R1())
    ecdh_shared = client_ecdh.exchange(ec.ECDH(), server_ecdh.public_key())
    
    # Post-Quantum: Kyber-768 KEM
    # Client generates keypair, server encapsulates
    kyber_public, kyber_secret = kyber768_keygen()
    ciphertext, kyber_shared = kyber768_encapsulate(kyber_public)
    
    # Combine both shared secrets
    combined = ecdh_shared + kyber_shared
    
    # Derive AES-256 key using HKDF
    aes_key = HKDF(
        algorithm=sha256(), length=32,
        salt=None, info=b"malware-submission-v1"
    ).derive(combined)
    
    return aes_key  # 256-bit AES key
```

### Component 3: Encryption & Integrity (AES-256-GCM + HMAC)

**What:** Encrypt the PE binary with AES-256-GCM (authenticated encryption), then add HMAC for additional integrity layer.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac, hashlib, os

def encrypt_binary(binary_data: bytes, aes_key: bytes):
    # AES-256-GCM (provides confidentiality + integrity)
    nonce = os.urandom(12)  # 96-bit nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, binary_data, associated_data=b"malware-sample")
    
    # Additional HMAC-SHA256 over (nonce + ciphertext) for non-repudiation
    mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()
    
    return nonce, ciphertext, mac

def decrypt_binary(nonce, ciphertext, mac, aes_key):
    # Verify HMAC first (fail fast)
    expected_mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise SecurityError("HMAC verification failed — payload tampered!")
    
    # Decrypt
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=b"malware-sample")
    return plaintext
```

### Component 4: Zero Trust Enforcement

**What:** Every single request is independently authenticated and authorized. No sessions, no cookies, no trust.

**Zero Trust Principles Applied:**
1. **Never trust, always verify** — Client cert verified on every request
2. **Least privilege** — Client can only submit binaries, not access results of other users
3. **Assume breach** — All internal traffic is encrypted, even on localhost
4. **Micro-segmentation** — Submission endpoint is separate from analysis endpoint
5. **Continuous validation** — Certificate expiry and revocation checked per-request

```python
# Server-side zero trust middleware
def verify_request(request):
    # 1. Verify client certificate (mTLS — handled by TLS layer)
    client_cert = request.environ.get('SSL_CLIENT_CERT')
    if not validate_certificate(client_cert, ca_cert):
        return 403, "Certificate validation failed"
    
    # 2. Check certificate not revoked (CRL check)
    if is_revoked(client_cert):
        return 403, "Certificate revoked"
    
    # 3. Extract client identity from cert CN
    client_id = extract_cn(client_cert)
    
    # 4. Rate limiting per client identity
    if rate_limit_exceeded(client_id):
        return 429, "Rate limit exceeded"
    
    # 5. Log for audit trail (non-repudiation)
    audit_log(client_id, request.path, timestamp=now())
    
    return 200, "Authorized"
```

---

## 4. Project File Structure

```
isproject/
├── certs/                      # PKI certificates
│   ├── generate_certs.sh       # Script to generate all certs
│   ├── ca.key / ca.crt
│   ├── server.key / server.crt
│   └── client.key / client.crt
├── server/
│   ├── app.py                  # Flask HTTPS server with mTLS
│   ├── crypto_utils.py         # AES-GCM, HMAC, Kyber helpers
│   └── zero_trust.py           # Auth middleware, rate limiting, audit
├── client/
│   ├── submit.py               # CLI client to submit malware binary
│   └── crypto_utils.py         # Client-side encryption
├── common/
│   └── protocol.py             # Shared message format (JSON schema)
├── tests/
│   ├── test_encryption.py      # Unit tests for AES-GCM
│   ├── test_integrity.py       # HMAC tampering tests
│   └── test_auth.py            # mTLS failure tests
├── demo.py                     # End-to-end demo script
└── README.md                   # Documentation
```

---

## 5. Simple Implementation Steps

### Step 1: Setup (Day 1)
- [ ] Create project structure
- [ ] `pip install flask cryptography pqcrypto`
- [ ] Generate CA + server + client certificates using OpenSSL
- [ ] Test basic HTTPS server with Flask + mTLS

### Step 2: Encryption Layer (Day 1–2)
- [ ] Implement `crypto_utils.py` (AES-256-GCM encrypt/decrypt)
- [ ] Implement HMAC-SHA256 signing and verification
- [ ] Write unit tests: encrypt → decrypt round-trip, tamper detection

### Step 3: Key Exchange (Day 2)
- [ ] Implement ECDH key exchange using `cryptography` library
- [ ] Implement Kyber-768 KEM (using `oqs-python` or `pqcrypto`)
- [ ] Implement hybrid key derivation (HKDF combining both shared secrets)
- [ ] Test: both sides derive the same AES key

### Step 4: Server API (Day 2–3)
- [ ] Flask app with mTLS (`ssl_context` with client cert verification)
- [ ] POST `/submit` — receive encrypted binary, decrypt, save
- [ ] Zero trust middleware (cert validation, rate limiting, audit log)
- [ ] Response: encrypted analysis result back to client

### Step 5: Client CLI (Day 3)
- [ ] `python submit.py --binary malware.exe --server https://localhost:5000`
- [ ] Performs key exchange → encrypts binary → sends → receives result

### Step 6: Demo & Tests (Day 3)
- [ ] End-to-end demo: submit a PE binary → server decrypts → returns "analysis complete"
- [ ] Attack demos:
  - Tampered payload → HMAC fails
  - No client cert → mTLS rejects
  - Expired cert → rejected
  - Modified ciphertext → AES-GCM auth tag fails

---

## 6. Threat Model & Mitigations

| Threat | Attack | Mitigation |
|--------|--------|------------|
| **Eavesdropping** | MITM intercepts binary | AES-256-GCM + TLS 1.3 encryption |
| **Tampering** | Modify binary in transit | HMAC-SHA256 + GCM auth tag |
| **Impersonation** | Attacker pretends to be client | Mutual TLS with X.509 certificates |
| **Replay** | Re-send old submission | Nonce per request + timestamp validation |
| **Quantum threat** | Future quantum computer breaks ECDH | Kyber-768 lattice-based KEM (NIST PQC standard) |
| **Cert compromise** | Stolen client key | CRL/OCSP revocation checking |
| **Privilege escalation** | Client accesses other users' results | Zero trust: identity-scoped access per request |

---

## 7. How This Links to Your FYP

```
[User submits PE binary]
        │
        ▼
┌─────────────────────────────────┐
│  IS PROJECT: Secure Submission  │  ◄── This project
│  mTLS + Kyber + AES-256-GCM    │
└────────────┬────────────────────┘
             │ (decrypted binary)
             ▼
┌─────────────────────────────────┐
│  FYP: Malware Analysis Pipeline │  ◄── Your FYP
│  Decompiler → Features → ML    │
└────────────┬────────────────────┘
             │ (classification result)
             ▼
┌─────────────────────────────────┐
│  IS PROJECT: Secure Response    │  ◄── This project
│  Encrypted result back to user  │
└─────────────────────────────────┘
```

**Presentation talking point:**
> "In our FYP, we built a malware classification pipeline. But how do you safely get the malware binary TO the analysis server? You can't just send malware over HTTP. Our IS project solves this: a zero-trust framework that ensures only authenticated analysts can submit samples, all transfers are encrypted with quantum-resistant algorithms, and every submission is integrity-verified and audit-logged."

---

## 8. Libraries Needed

```
pip install flask cryptography oqs  # or pqcrypto
```

| Library | Purpose |
|---------|---------|
| `flask` | HTTPS server |
| `cryptography` | AES-GCM, ECDH, X.509, HMAC, HKDF |
| `oqs` (liboqs-python) | Kyber-768 post-quantum KEM |
| `OpenSSL` (CLI) | Certificate generation |
