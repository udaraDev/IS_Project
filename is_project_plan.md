# IS Project — Implementation Plan (MVA)

## Zero Trust Secure Communication Framework for Malware Sample Submission Using Mutual Authentication, End-to-End Encryption and Post-Quantum Readiness

> **Deadline:** Evaluation week starting 18th May 2026
> **Scope:** Minimal Viable Architecture — three pillars: **Mutual Authentication** (mTLS), **E2E Encryption** (AES-256-GCM), **Post-Quantum Readiness** (Hybrid ECDH + Kyber-768)
> **Link to FYP:** Secures the binary submission pipeline of your malware static analysis project

---

## 1. System Architecture

```
┌──────────────────┐                              ┌──────────────────────┐
│   CLIENT (CLI)   │                              │   SERVER (Flask)     │
│                  │                              │                      │
│ 1. Load PE file  │── Mutual TLS (mTLS) ──────►  │ 1. Verify client cert│
│ 2. Hybrid key    │── ECDH + Kyber-768 KEM ───►  │ 2. Derive hybrid key │
│    exchange      │                              │    HKDF(ECDH ∥ Kyber)│
│ 3. Encrypt file  │── AES-256-GCM payload ────►  │ 3. Verify HMAC       │
│ 4. HMAC sign     │── HMAC-SHA256 ────────────►  │ 4. Decrypt binary    │
│ 5. RSA sign meta │── RSA-2048 signature ─────►  │ 5. Verify signature  │
│                  │                              │ 6. Log submission    │
│                  │◄── Encrypted result ────────  │ 7. Return result     │
└──────────────────┘                              └──────────────────────┘
```

### Communication Flow (Step by Step)

```
CLIENT                                          SERVER
  │                                               │
  │──── 1. TLS Handshake (mTLS) ─────────────────►│  Both sides present certs
  │◄──── Mutual authentication complete ──────────│
  │                                               │
  │──── 2. Send ECDH pub + Kyber pub key ────────►│
  │◄──── Server ECDH pub + Kyber ciphertext ─────│  Hybrid key exchange
  │                                               │
  │  3. Client-side:                              │
  │     - ECDH shared secret + Kyber shared secret │
  │     - HKDF(ecdh_secret ∥ kyber_secret) → AES  │
  │     - AES-256-GCM encrypt(binary)             │
  │     - HMAC-SHA256(nonce + ciphertext)          │
  │     - RSA sign(submission metadata)            │
  │                                               │
  │──── 4. POST /submit ─────────────────────────►│
  │      {nonce, ciphertext, hmac, signature,      │
  │       ecdh_public_key, metadata}               │
  │                                               │  5. Server-side:
  │                                               │     - Verify HMAC
  │                                               │     - Verify RSA signature
  │                                               │     - Decrypt binary
  │                                               │     - Audit log entry
  │                                               │
  │◄──── 6. Encrypted response ──────────────────│  {status, sha256_of_binary}
  │                                               │
```

---

## 2. Security Properties — Mapped to Title Pillars

| Title Pillar | Property | Technique | Implementation |
|-------------|----------|-----------|----------------|
| **Mutual Authentication** | Authentication | Mutual TLS (mTLS) | Both client and server present X.509 certificates signed by shared CA |
| **Mutual Authentication** | Non-repudiation | RSA-2048 digital signatures (PSS) | Client signs submission metadata; server can prove who submitted what |
| **E2E Encryption** | Confidentiality | AES-256-GCM | Binary payload encrypted with 256-bit symmetric key derived from hybrid KEM |
| **E2E Encryption** | Integrity | HMAC-SHA256 + GCM auth tag | Dual integrity: GCM at cipher layer, HMAC at application layer |
| **E2E Encryption** | Key Exchange | ECDH (P-256) + HKDF | Classical ephemeral key agreement with forward secrecy |
| **Post-Quantum Readiness** | PQ Key Exchange | Kyber-768 KEM (FIPS 203 / ML-KEM) | Lattice-based KEM via `kyber-py` — hybrid combined with ECDH |
| — | Zero Trust | Per-request cert verification | No sessions, no cookies — every request re-authenticated via mTLS |

---

## 3. Implementation Components

### Component 1: Certificate Authority (CA) & Mutual TLS

**What:** Create a self-signed root CA, issue client + server certificates for mutual authentication.

**Security Property:** Authentication — both parties prove identity before any data is exchanged.

```
certs/
├── ca.key              # Root CA private key (4096-bit RSA)
├── ca.crt              # Root CA certificate
├── server.key          # Server private key (2048-bit RSA)
├── server.crt          # Server certificate (signed by CA)
├── client.key          # Client private key (2048-bit RSA)
└── client.crt          # Client certificate (signed by CA)
```

**Generation Script (`certs/generate_certs.sh`):**
```bash
#!/bin/bash
set -e
mkdir -p certs && cd certs

# 1. Create Root CA (4096-bit for CA, stronger than leaf certs)
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 365 -out ca.crt \
    -subj "/CN=MalwareAnalysisCA/O=ISProject/C=LK"

# 2. Server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=analysis-server/O=ISProject/C=LK"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365

# 3. Client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
    -subj "/CN=analyst-client/O=ISProject/C=LK"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365

# Cleanup CSRs
rm -f *.csr

echo "✅ All certificates generated successfully"
```

**Flask mTLS Configuration:**
```python
# server/app.py — SSL context setup
import ssl

def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('certs/server.crt', 'certs/server.key')
    ctx.load_verify_locations('certs/ca.crt')
    ctx.verify_mode = ssl.CERT_REQUIRED          # ← Forces client cert
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3 # ← TLS 1.3 only
    return ctx
```

---

### Component 2: Hybrid Key Exchange (ECDH P-256 + Kyber-768 + HKDF)

**What:** Combine classical ECDH with post-quantum Kyber-768 KEM. Both shared secrets are concatenated and fed into HKDF to derive the AES session key.

**Security Properties:**
- **Key Exchange** — both sides derive the same symmetric key without transmitting it
- **Post-Quantum Readiness** — even if ECDH is broken by a quantum computer, Kyber's lattice-based security still protects the session key

**Why Hybrid?** If Kyber is later found to have a classical vulnerability, ECDH still protects the session. If a quantum computer breaks ECDH, Kyber still protects. Both must be broken simultaneously.

```python
# common/crypto_utils.py — Hybrid Key Exchange
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from kyber import Kyber768  # pip install kyber-py (pure Python, no C deps)

# --- ECDH (Classical) ---
def generate_ecdh_keypair():
    """Generate an ephemeral ECDH key pair (P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_bytes

def ecdh_derive(private_key, peer_public_key_bytes: bytes) -> bytes:
    """Compute ECDH shared secret."""
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
    return private_key.exchange(ec.ECDH(), peer_public_key)

# --- Kyber-768 (Post-Quantum) ---
def kyber_keygen():
    """Generate Kyber-768 keypair. Returns (public_key, secret_key)."""
    pk, sk = Kyber768.keygen()
    return pk, sk

def kyber_encapsulate(public_key):
    """Encapsulate: returns (ciphertext, shared_secret)."""
    ct, ss = Kyber768.enc(public_key)
    return ct, ss

def kyber_decapsulate(ciphertext, secret_key):
    """Decapsulate: returns shared_secret."""
    ss = Kyber768.dec(ciphertext, secret_key)
    return ss

# --- Hybrid Key Derivation ---
def derive_hybrid_aes_key(ecdh_shared: bytes, kyber_shared: bytes) -> bytes:
    """Combine ECDH + Kyber shared secrets via HKDF to get AES-256 key."""
    combined = ecdh_shared + kyber_shared
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,              # 256 bits
        salt=None,
        info=b"malware-submission-hybrid-v1"
    ).derive(combined)
    return aes_key
```

**Design Justification (for viva):**
- **Why hybrid ECDH + Kyber?** — Defence in depth: the session key is secure as long as *either* algorithm remains unbroken. This follows NIST's recommended migration strategy.
- **Why Kyber-768?** — NIST FIPS 203 (ML-KEM) standard. 768 provides ~192-bit post-quantum security. The `kyber-py` library is a pure-Python implementation suitable for demonstration.
- **Why HKDF?** — Raw key material is biased; HKDF extracts uniform randomness. The `info` parameter binds the key to our protocol, preventing cross-protocol attacks.
- **Why ECDH (P-256)?** — Provides classical forward secrecy. NIST-approved, 128-bit security level.

---

### Component 3: Encryption & Integrity (AES-256-GCM + HMAC-SHA256)

**What:** Encrypt the PE binary with AES-256-GCM (authenticated encryption), then add an HMAC for defence-in-depth integrity.

**Security Properties:** Confidentiality (AES-GCM) + Integrity (GCM auth tag + HMAC-SHA256).

```python
# common/crypto_utils.py — Encryption & Integrity
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac, hashlib, os

def encrypt_binary(binary_data: bytes, aes_key: bytes) -> dict:
    """
    Encrypt binary with AES-256-GCM and compute HMAC.

    Returns dict with nonce, ciphertext (includes GCM tag), and HMAC.
    """
    nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, binary_data, associated_data=b"malware-sample")

    # Application-layer HMAC over (nonce || ciphertext)
    mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "hmac": mac
    }

def decrypt_binary(nonce: bytes, ciphertext: bytes, mac: bytes, aes_key: bytes) -> bytes:
    """
    Verify HMAC first (fail fast), then decrypt with AES-256-GCM.
    """
    # 1. Verify application-layer HMAC
    expected_mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed — payload tampered!")

    # 2. Decrypt (GCM auth tag verified internally)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=b"malware-sample")
    return plaintext
```

**Design Justification (for viva):**
- **Why AES-GCM over AES-CBC?** — GCM is an AEAD cipher: it provides authenticated encryption in a single pass. CBC requires a separate MAC (e.g., Encrypt-then-MAC) and is vulnerable to padding oracle attacks.
- **Why HMAC if GCM already authenticates?** — Defence in depth. GCM authenticates at the cipher layer; HMAC provides an independent application-layer check that also covers the nonce. If a GCM implementation bug were found, HMAC still catches tampering.
- **Why `compare_digest`?** — Prevents timing side-channel attacks. Standard `==` comparison leaks information about which byte differs.

---

### Component 4: Digital Signatures (RSA-2048) — Non-Repudiation

**What:** Client signs submission metadata with its RSA private key. Server can later prove who submitted what.

**Security Property:** Non-repudiation — the client cannot deny having submitted a particular binary.

```python
# common/crypto_utils.py — Digital Signatures
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def sign_metadata(metadata: bytes, private_key_path: str) -> bytes:
    """Sign submission metadata with RSA-2048 (PSS padding)."""
    with open(private_key_path, 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        metadata,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(metadata: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verify RSA signature on submission metadata."""
    public_key = load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            metadata,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
```

**Design Justification (for viva):**
- **Why RSA-PSS over PKCS#1 v1.5?** — PSS is provably secure under standard assumptions; PKCS#1 v1.5 has known signature forgery vulnerabilities (Bleichenbacher's attack).
- **Why sign metadata and not the binary itself?** — Signing a multi-MB binary is slow. We sign a SHA-256 hash of the binary + timestamp + client ID, which is sufficient for non-repudiation.

---

## 4. Project File Structure

```
isproject/
├── certs/
│   ├── generate_certs.sh          # OpenSSL script to generate all certs
│   ├── ca.key / ca.crt            # Root CA
│   ├── server.key / server.crt    # Server keypair
│   └── client.key / client.crt    # Client keypair
├── server/
│   └── app.py                     # Flask HTTPS server with mTLS
├── client/
│   └── submit.py                  # CLI client to submit PE binary
├── common/
│   └── crypto_utils.py            # Shared: ECDH, Kyber, AES-GCM, HMAC, RSA
├── tests/
│   ├── test_crypto.py             # Encrypt/decrypt round-trip, tamper detection
│   ├── test_kyber.py              # Kyber KEM keygen/encap/decap tests
│   └── test_auth.py               # mTLS rejection tests
├── attack_demos.py                # 4 attack scenarios (viva demo)
├── demo.py                        # End-to-end happy path demo
├── requirements.txt               # flask, cryptography, kyber-py
└── README.md
```

---

## 5. Implementation Steps

### Step 1: Certificates & mTLS Server (Day 1 — Morning)

**Goal:** A running HTTPS server that rejects clients without valid certificates.

- [ ] Create `certs/generate_certs.sh` and run it to generate CA + server + client certs
- [ ] Create `server/app.py` with Flask + mTLS SSL context
- [ ] Test: `curl` without client cert → **rejected (403)**
- [ ] Test: `curl` with client cert → **accepted (200)**

```python
# server/app.py — Minimal mTLS server
from flask import Flask, request, jsonify
import ssl, json

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    # Extract client identity from mTLS cert
    client_cert = request.environ.get('peercert', {})
    return jsonify({"status": "ok", "client": "authenticated"})

@app.route('/submit', methods=['POST'])
def submit():
    # Will be expanded in Step 4
    return jsonify({"status": "received"})

if __name__ == '__main__':
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain('certs/server.crt', 'certs/server.key')
    ctx.load_verify_locations('certs/ca.crt')
    ctx.verify_mode = ssl.CERT_REQUIRED
    app.run(host='0.0.0.0', port=5000, ssl_context=ctx)
```

**Checkpoint:** Server running on `https://localhost:5000`, rejects unauthenticated clients. ✅

---

### Step 2: Crypto Utilities (Day 1 — Afternoon)

**Goal:** All cryptographic operations working and tested in isolation.

- [ ] `pip install kyber-py` — verify it works on your machine
- [ ] Implement `common/crypto_utils.py`:
  - `generate_ecdh_keypair()` / `ecdh_derive()`
  - `kyber_keygen()` / `kyber_encapsulate()` / `kyber_decapsulate()`
  - `derive_hybrid_aes_key()` — HKDF(ecdh_secret ∥ kyber_secret)
  - `encrypt_binary()` / `decrypt_binary()`
  - `sign_metadata()` / `verify_signature()`
- [ ] Write `tests/test_crypto.py`:
  - Kyber: keygen → encapsulate → decapsulate produces same shared secret
  - Hybrid: ECDH + Kyber → HKDF → both sides derive same AES key
  - AES-GCM: encrypt → decrypt round-trip
  - HMAC: tampering detected
  - RSA: valid signature passes, forged signature fails

```python
# tests/test_crypto.py — Key tests
import pytest
from common.crypto_utils import *

def test_ecdh_key_agreement():
    """Both parties derive the same AES key."""
    client_priv, client_pub = generate_ecdh_keypair()
    server_priv, server_pub = generate_ecdh_keypair()

    client_aes = derive_aes_key(client_priv, server_pub)
    server_aes = derive_aes_key(server_priv, client_pub)
    assert client_aes == server_aes

def test_encrypt_decrypt_roundtrip():
    """Binary survives encrypt → decrypt."""
    key = os.urandom(32)
    original = b"MZ\x90\x00" + os.urandom(1000)  # Fake PE header
    result = encrypt_binary(original, key)
    recovered = decrypt_binary(result['nonce'], result['ciphertext'], result['hmac'], key)
    assert recovered == original

def test_tamper_detection():
    """Modified ciphertext triggers HMAC failure."""
    key = os.urandom(32)
    result = encrypt_binary(b"test data", key)
    tampered = result['ciphertext'][:-1] + bytes([result['ciphertext'][-1] ^ 0xFF])
    with pytest.raises(ValueError, match="HMAC verification failed"):
        decrypt_binary(result['nonce'], tampered, result['hmac'], key)
```

**Checkpoint:** `pytest tests/test_crypto.py` — all green. ✅

---

### Step 3: Client CLI (Day 2 — Morning)

**Goal:** A working CLI that submits a binary file to the server.

- [ ] Implement `client/submit.py`:
  - Load binary file from disk
  - Perform ECDH key exchange with server
  - Encrypt binary + compute HMAC
  - Sign metadata with client's RSA key
  - POST to `/submit` with mTLS

```python
# client/submit.py — Usage
# python client/submit.py --binary samples/test.exe --server https://localhost:5000
```

- [ ] Implement server-side `/submit` handler:
  - Receive ECDH public key from client
  - Derive shared AES key
  - Verify HMAC → Verify RSA signature → Decrypt binary
  - Log submission to audit file
  - Return encrypted acknowledgment

**Checkpoint:** `python client/submit.py --binary test.exe` → server receives, decrypts, and logs. ✅

---

### Step 4: Attack Demos & E2E Demo (Day 2 — Afternoon)

**Goal:** A demo script for the viva that shows 4 attacks failing.

- [ ] Create `attack_demos.py` with 4 attack scenarios:

```python
# attack_demos.py — Viva demonstration script

def attack_1_no_client_cert():
    """ATTACK: Connect without a client certificate.
    EXPECTED: mTLS rejects connection (SSL handshake failure)."""

def attack_2_tampered_payload():
    """ATTACK: Flip a byte in the encrypted payload.
    EXPECTED: HMAC verification fails on server side."""

def attack_3_forged_signature():
    """ATTACK: Submit with a different RSA key (impersonation).
    EXPECTED: RSA signature verification fails."""

def attack_4_modified_ciphertext():
    """ATTACK: Modify ciphertext after HMAC (bypass HMAC, but GCM catches it).
    EXPECTED: AES-GCM authentication tag verification fails."""
```

- [ ] Create `demo.py` — happy path end-to-end:
  1. Start server
  2. Client submits binary
  3. Server decrypts and returns result
  4. Print audit log

**Checkpoint:** All 4 attacks fail with clear error messages. Happy path works. ✅

---

### Step 5: Presentation & Viva Prep (Day 2 — Evening)

- [ ] Prepare slides covering:
  1. Problem statement (why secure malware submission?)
  2. Architecture diagram
  3. Security properties table (map each to technique)
  4. Threat model & mitigations
  5. Live demo plan
  6. FYP integration
  7. Future work (PQC / Kyber hybrid)
- [ ] Rehearse viva Q&A (see Section 8)

---

## 6. Threat Model & Mitigations

| Threat | Attack Vector | Mitigation | Demo |
|--------|--------------|------------|------|
| **Eavesdropping** | MITM intercepts binary in transit | AES-256-GCM + TLS 1.3 double encryption | ✅ Payload is encrypted |
| **Tampering** | Modify binary during transmission | HMAC-SHA256 + GCM authentication tag | ✅ `attack_2` |
| **Impersonation** | Attacker pretends to be authorized client | Mutual TLS — server verifies client X.509 cert | ✅ `attack_1` |
| **Forgery** | Submit binary under someone else's identity | RSA-2048 digital signature on metadata | ✅ `attack_3` |
| **Replay** | Re-send a previously valid submission | Ephemeral ECDH keys + nonce per request | Nonce uniqueness |
| **Quantum threat** | Future quantum computer breaks ECDH | Hybrid ECDH + Kyber-768 KEM — AES key secure if either algorithm holds | ✅ Hybrid key exchange demo |

---

## 7. FYP Integration

```
[User submits PE binary]
        │
        ▼
┌─────────────────────────────────┐
│  IS PROJECT: Secure Submission  │  ◄── This project
│  mTLS + Hybrid(ECDH+Kyber)     │
│  + AES-256-GCM + HMAC + RSA     │
└────────────┬────────────────────┘
             │ (decrypted, verified binary)
             ▼
┌─────────────────────────────────┐
│  FYP: Malware Analysis Pipeline │  ◄── Your FYP
│  Decompiler → CFG → GNN/ML     │
└────────────┬────────────────────┘
             │ (classification result)
             ▼
┌─────────────────────────────────┐
│  IS PROJECT: Secure Response    │  ◄── This project
│  Encrypted result back to user  │
└─────────────────────────────────┘
```

**Presentation talking point:**
> "In our FYP, we built a malware classification pipeline using graph neural networks on control flow graphs. But how do you safely get the malware binary TO the analysis server? You can't just send malware over HTTP — it could be intercepted, tampered with, or submitted by unauthorized users. Our IS project solves this with a zero-trust framework featuring three pillars: **mutual authentication** via mTLS, **end-to-end encryption** via AES-256-GCM with HMAC integrity, and **post-quantum readiness** via a hybrid ECDH + Kyber-768 key exchange that remains secure even against future quantum computers."

---

## 8. Viva Preparation — Expected Questions & Strong Answers

| Question | Answer |
|----------|--------|
| "Why AES-256-GCM over AES-CBC?" | "GCM is an AEAD mode — it provides authenticated encryption in one pass. CBC requires a separate MAC step and is vulnerable to padding oracle attacks (e.g., POODLE)." |
| "Why HMAC if GCM already authenticates?" | "Defence in depth. GCM operates at the cipher layer; HMAC provides an independent application-layer integrity check covering the nonce. If a GCM implementation flaw were discovered, HMAC still catches tampering." |
| "Why ECDH over RSA key transport?" | "ECDH provides forward secrecy. If the server's long-term key is later compromised, past session keys remain safe because each session used ephemeral keys that were never stored." |
| "Why P-256 specifically?" | "NIST-approved curve with 128-bit security level. Widely supported, well-analyzed, and performant. Avoids the complexity of newer curves like X25519 for a demonstration project." |
| "What about post-quantum threats?" | "We use a hybrid key exchange: classical ECDH combined with Kyber-768 (NIST FIPS 203 / ML-KEM). Both shared secrets are concatenated and fed into HKDF. The AES key is secure as long as *either* algorithm remains unbroken — so even if a quantum computer breaks ECDH, Kyber still protects the session." |
| "How is this Zero Trust?" | "No sessions, no cookies, no persistent trust. Every API request requires a valid mTLS client certificate. The server re-authenticates on every call and logs each action to an audit trail." |
| "What if a client's private key is compromised?" | "The compromised certificate can be revoked by the CA. In production, we'd implement CRL or OCSP checking. For this demo, the CA simply stops issuing/trusting that certificate." |
| "Why RSA-PSS over PKCS#1 v1.5?" | "PSS has a formal security proof under standard assumptions. PKCS#1 v1.5 signatures are vulnerable to Bleichenbacher-style forgery attacks." |
| "Could an attacker replay a submission?" | "Each session uses ephemeral ECDH keys, so the AES key is unique per submission. A replayed ciphertext would be encrypted under a key the server no longer has. Additionally, each encryption uses a random 96-bit nonce." |

---

## 9. Libraries & Requirements

```
# requirements.txt
flask>=3.0
cryptography>=42.0
kyber-py>=1.2.0
pytest>=8.0
```

| Library | Purpose | Install Risk |
|---------|---------|-------------|
| `flask` | HTTPS server with mTLS | 🟢 None — pure Python |
| `cryptography` | AES-GCM, ECDH, HKDF, HMAC, RSA, X.509 | 🟢 None — wheels available |
| `kyber-py` | Kyber-768 post-quantum KEM (FIPS 203) | 🟢 None — **pure Python**, no C deps |
| `pytest` | Testing | 🟢 None |
| `OpenSSL` (CLI) | Certificate generation only | 🟢 Pre-installed on most systems |

> **No C compilation required. No native dependencies. `kyber-py` is pure Python. Everything installs cleanly on Windows with `pip install -r requirements.txt`.**

---

## 10. Deliverables Checklist

| # | Deliverable | Course Requirement | Status |
|---|-------------|-------------------|--------|
| 1 | Self-signed CA + mTLS certs | Mutual Authentication | ☐ |
| 2 | ECDH key exchange | Classical key agreement | ☐ |
| 3 | Kyber-768 KEM (kyber-py) | Post-Quantum Readiness | ☐ |
| 4 | Hybrid HKDF key derivation | Combines ECDH + Kyber | ☐ |
| 5 | AES-256-GCM encryption/decryption | E2E Encryption | ☐ |
| 6 | HMAC-SHA256 integrity verification | Integrity | ☐ |
| 7 | RSA-2048 digital signatures | Non-repudiation | ☐ |
| 8 | Flask server with `/submit` endpoint | Secure communication | ☐ |
| 9 | Client CLI (`submit.py`) | Two-party communication | ☐ |
| 10 | Unit tests (crypto + Kyber) | Correctness validation | ☐ |
| 11 | `attack_demos.py` (4 attack scenarios) | Threat mitigation proof | ☐ |
| 12 | `demo.py` (end-to-end) | Live demonstration | ☐ |
| 13 | Threat model table | Design justification | ☐ |
| 14 | Presentation slides | Presentation | ☐ |
