# Zero Trust Secure Communication Framework
# Complete System Documentation (A-Z)

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Complete Communication Flow](#3-complete-communication-flow)
4. [Security Properties](#4-security-properties)
5. [Deliverables & Implementations](#5-deliverables--implementations)
6. [Attack Demonstrations](#6-attack-demonstrations)
7. [Threat Model](#7-threat-model)
8. [Project Structure](#8-project-structure)
9. [How to Run](#9-how-to-run)
10. [Viva Q&A Reference](#10-viva-qa-reference)

---

# 1. Project Overview

**Title:** Zero Trust Secure Communication Framework for Malware Sample Submission Using Mutual Authentication, End-to-End Encryption and Post-Quantum Readiness

**Problem:** In a malware analysis pipeline, PE binaries must be transferred from an analyst's machine to an analysis server. Sending malware over unprotected HTTP risks interception, tampering, unauthorized submissions, and future quantum-based attacks.

**Solution:** A client-server framework with three security pillars:

| Pillar | What it Means | How We Achieve It |
|--------|--------------|-------------------|
| **Mutual Authentication** | Both client AND server prove identity before any data flows | Mutual TLS (mTLS) with X.509 certificates |
| **End-to-End Encryption** | Binary is encrypted from client to server; no intermediary can read it | AES-256-GCM with HMAC-SHA256 integrity |
| **Post-Quantum Readiness** | Session key remains secure even if future quantum computers break classical crypto | Hybrid ECDH + Kyber-768 key exchange |

**Link to FYP:** This framework secures the submission pipeline of our malware static analysis FYP (Decompiler -> CFG -> GNN/ML classification).

---

# 2. System Architecture

```
CLIENT (CLI)                                    SERVER (Flask HTTPS)
+------------------+                            +----------------------+
|                  |                            |                      |
| 1. Load PE file  |-- Mutual TLS (mTLS) -----> | 1. Verify client cert|
| 2. Hybrid key    |-- ECDH + Kyber-768 KEM --> | 2. Derive hybrid key |
|    exchange      |                            |    HKDF(ECDH||Kyber) |
| 3. Encrypt file  |-- AES-256-GCM payload ---> | 3. Verify HMAC       |
| 4. HMAC sign     |-- HMAC-SHA256 -----------> | 4. Decrypt binary    |
| 5. RSA sign meta |-- RSA-2048 signature ----> | 5. Verify signature  |
|                  |                            | 6. Log submission    |
|                  |<-- Encrypted result ------- | 7. Return result     |
+------------------+                            +----------------------+
```

**Two-phase protocol:**
- **Phase 1 - `/init`**: mTLS handshake + hybrid key exchange (ECDH + Kyber)
- **Phase 2 - `/submit`**: Encrypted payload + HMAC + RSA signature

---

# 3. Complete Communication Flow

## Step 1: Mutual TLS Handshake

**What happens:**
The client connects to `https://localhost:5443`. The TLS handshake requires BOTH sides to present X.509 certificates signed by the same Certificate Authority (CA).

**Server SSL configuration** (`server/app.py` lines 115-124):
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('certs/server.crt', 'certs/server.key')
ctx.load_verify_locations('certs/ca.crt')
ctx.verify_mode = ssl.CERT_REQUIRED       # Client MUST present a cert
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
```

**Client sends cert** (`client/submit.py` lines 31-36):
```python
r = requests.post(
    f"{server}/init",
    json=init_payload,
    cert=(str(CERTS / "client.crt"), str(CERTS / "client.key")),  # Client cert
    verify=str(CERTS / "ca.crt"),  # Verify server cert against CA
)
```

**What this achieves:** Authentication - both parties prove identity. If a client has no cert or an invalid cert, the TLS handshake fails immediately and no data is exchanged.

---

## Step 2: Hybrid Key Exchange (ECDH + Kyber-768)

**What happens:** The client and server independently derive the same AES-256 session key using two key exchange mechanisms combined.

### 2a. Client generates keypairs

```python
# Client generates ECDH keypair (classical)
client_ecdh_priv, client_ecdh_pub = generate_ecdh_keypair()
# Client generates Kyber-768 keypair (post-quantum)
kyber_kp = kyber_keygen()
```

The client sends both public keys to the server via `POST /init`.

### 2b. Server performs key exchange

**Server** (`server/app.py` lines 46-54):
```python
# Server generates its own ECDH keypair
server_ecdh_priv, server_ecdh_pub = generate_ecdh_keypair()
# ECDH: Server computes shared secret using client's ECDH public key
ecdh_shared = ecdh_derive(server_ecdh_priv, client_ecdh_pub)
# Kyber: Server encapsulates to client's Kyber public key
kyber_ct, kyber_shared = kyber_encapsulate(client_kyber_pk)
# Combine both shared secrets via HKDF
aes_key = derive_hybrid_aes_key(ecdh_shared, kyber_shared)
```

Server returns: `server_ecdh_pub` + `kyber_ciphertext`

### 2c. Client derives same key

**Client** (`client/submit.py` lines 41-43):
```python
ecdh_shared = ecdh_derive(client_ecdh_priv, b64d(init["server_ecdh_pub"]))
kyber_shared = kyber_decapsulate(b64d(init["kyber_ciphertext"]), kyber_kp.secret_key)
aes_key = derive_hybrid_aes_key(ecdh_shared, kyber_shared)
```

### 2d. HKDF Key Derivation

Both secrets are concatenated and passed through HKDF (`crypto_utils.py` lines 220-233):

```python
def derive_hybrid_aes_key(ecdh_shared, kyber_shared):
    combined = ecdh_shared + kyber_shared     # Concatenate both secrets
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,                             # 256-bit AES key
        salt=None,
        info=b"malware-submission-hybrid-v1"   # Protocol-specific context
    ).derive(combined)
```

```
ECDH shared secret (32 bytes)   ---+
                                    +--> HKDF-SHA256 --> AES-256 key (32 bytes)
Kyber shared secret (32 bytes)  ---+
```

**Key insight:** Both client and server now have the SAME AES-256 key, without ever transmitting it. An attacker must break BOTH ECDH AND Kyber to recover this key.

---

## Step 3: AES-256-GCM Encryption

**What happens:** The client encrypts the PE binary with AES-256-GCM.

**Implementation** (`crypto_utils.py` lines 240-266):
```python
def encrypt_binary(binary_data, aes_key, aad=b"malware-sample"):
    nonce = os.urandom(12)                    # Random 96-bit nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, binary_data, aad)  # Encrypt + auth tag
    # ... HMAC computed below
```

- **Nonce**: 12 bytes of cryptographically secure randomness. Ensures the same plaintext encrypts to different ciphertext each time (replay protection).
- **AAD (Associated Authenticated Data)**: `b"malware-sample"` is bound to the ciphertext. If AAD doesn't match at decryption, GCM rejects it.
- **GCM Auth Tag**: Automatically appended to ciphertext. Provides integrity at the cipher layer.

---

## Step 4: HMAC-SHA256 Integrity Protection

**What happens:** An HMAC is computed over `nonce || ciphertext` as an additional integrity layer.

```python
mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()
```

**Why HMAC if GCM already authenticates?**
- **Defence in depth**: GCM authenticates at the cipher layer; HMAC provides an independent check at the application layer.
- If a GCM implementation bug were discovered, HMAC still catches tampering.
- HMAC also covers the nonce, which GCM's auth tag does not independently verify.

**Server-side verification** (`crypto_utils.py` lines 283-295):
```python
expected_mac = hmac.new(aes_key, nonce + ciphertext, hashlib.sha256).digest()
if not hmac.compare_digest(received_mac, expected_mac):
    raise ValueError("HMAC verification failed")
```

`compare_digest` is used instead of `==` to prevent **timing side-channel attacks**.

---

## Step 5: RSA-PSS Digital Signature (Non-Repudiation)

**What happens:** The client signs submission metadata with its RSA private key.

**Metadata signed:**
```python
metadata = {
    "client_id": "analyst-client",
    "filename": "sample_pe.bin",
    "timestamp": 1747490000,
    "purpose": "malware-sample-submission"
}
```

**Signing** (`crypto_utils.py` lines 310-332):
```python
signature = private_key.sign(
    metadata,
    padding.PSS(                          # Probabilistic Signature Scheme
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**Why RSA-PSS over PKCS#1 v1.5?** PSS has a formal security proof. PKCS#1 v1.5 is vulnerable to Bleichenbacher's signature forgery attack.

**Why sign metadata, not the binary?** The binary can be multi-MB. Signing a small metadata JSON (which includes a timestamp and client ID) is fast and sufficient for non-repudiation.

---

## Step 6: Server Verification & Decryption

The server performs checks in this order (`server/app.py` lines 67-112):

1. **Session validation**: Check session ID exists and hasn't expired (5-min TTL)
2. **RSA signature verification**: Verify metadata signature against client certificate
3. **HMAC verification**: Check HMAC-SHA256 over nonce+ciphertext
4. **AES-GCM decryption**: Decrypt binary (GCM auth tag verified internally)
5. **SHA-256 hash**: Compute hash of decrypted binary for audit
6. **Audit log**: Write timestamped entry to `logs/audit.log`
7. **Encrypted response**: Send result back encrypted with same AES key

---

## Step 7: Encrypted Response

```python
response_plain = f"ACCEPTED: {filename} sha256={digest}".encode()
encrypted_response = encrypt_binary(response_plain, aes_key, aad=b"server-response")
```

The response is encrypted with the same session key, ensuring end-to-end encryption in both directions.

---

# 4. Security Properties

## 4.1 Confidentiality

**Meaning:** Only the intended recipient can read the data. An eavesdropper intercepting the communication sees only encrypted bytes.

**How we achieve it:**
- **TLS 1.3**: All communication is encrypted at the transport layer
- **AES-256-GCM**: Binary payload is encrypted at the application layer with a 256-bit key
- **Double encryption**: Even if TLS is somehow bypassed, the payload is independently encrypted

**Relevant code:** `crypto_utils.py` `encrypt_binary()` / `decrypt_binary()`

---

## 4.2 Integrity

**Meaning:** Data cannot be modified in transit without detection. If even a single bit changes, the system detects and rejects it.

**How we achieve it (two layers):**
1. **HMAC-SHA256** (application layer): `hmac.new(key, nonce + ciphertext, sha256)` - catches any modification to the encrypted payload
2. **AES-GCM auth tag** (cipher layer): Built into GCM mode - catches modifications even if HMAC is bypassed

**Relevant code:** `crypto_utils.py` lines 256-260 (HMAC generation), lines 283-295 (HMAC verification)

---

## 4.3 Authentication

**Meaning:** Both parties prove they are who they claim to be. No impersonation is possible.

**How we achieve it:**
- **Mutual TLS (mTLS)**: Both client and server present X.509 certificates signed by a trusted CA
- Unlike normal HTTPS (server-only auth), mTLS verifies the CLIENT too
- `ssl.CERT_REQUIRED` in server SSL context forces client certificate verification

**Relevant code:** `server/app.py` `create_ssl_context()`, `client/submit.py` `cert=(...)` parameter

---

## 4.4 Non-Repudiation

**Meaning:** The client cannot deny having submitted a particular binary. The server has cryptographic proof of who submitted what and when.

**How we achieve it:**
- **RSA-PSS digital signatures**: Client signs metadata with its private key
- Only the holder of `client.key` can produce a valid signature
- The server can later prove: "This specific client submitted this file at this time"

**Relevant code:** `crypto_utils.py` `sign_metadata()` / `verify_signature()`

---

## 4.5 Forward Secrecy

**Meaning:** Even if long-term keys (certificates) are compromised in the future, past communication sessions remain protected.

**How we achieve it:**
- **Ephemeral ECDH**: Each session generates fresh ECDH keypairs
- The session key is derived from ephemeral keys that are never stored
- After the session, the ephemeral private keys are discarded (garbage collected)

---

## 4.6 Post-Quantum Readiness

**Meaning:** The system remains secure even against future quantum computers that could break classical cryptography using Shor's Algorithm.

**The threat:** A quantum computer running Shor's Algorithm can break RSA and ECDH in polynomial time.

**How we achieve it:**
- **Kyber-768 (ML-KEM)**: NIST FIPS 203 standardized lattice-based Key Encapsulation Mechanism
- **Hybrid approach**: `HKDF(ECDH_secret || Kyber_secret)` - the AES key is secure as long as EITHER algorithm remains unbroken
- If a quantum computer breaks ECDH, Kyber still protects the session
- If Kyber is found to have a classical vulnerability, ECDH still protects

**Relevant code:** `crypto_utils.py` `kyber_keygen()`, `kyber_encapsulate()`, `kyber_decapsulate()`, `derive_hybrid_aes_key()`

---

## 4.7 Zero Trust

**Meaning:** "Never trust, always verify." No implicit trust is granted to any entity. Every request is independently authenticated.

**How we achieve it:**
- **Per-request mTLS**: Every API call requires a valid client certificate
- **No sessions/cookies**: No persistent trust tokens
- **Session TTL**: Key exchange sessions expire after 5 minutes
- **Single-use sessions**: Session keys are consumed (deleted) after use
- **Audit logging**: Every submission is logged with client ID, filename, timestamp, and SHA-256 hash

---

# 5. Deliverables & Implementations

## 5.1 Self-Signed Certificate Authority (CA)

**What:** A root CA that issues and signs certificates for both the server and client.

**Files:**
- `ca.key` - CA private key (4096-bit RSA)
- `ca.crt` - CA certificate (self-signed)
- `server.key/server.crt` - Server keypair (2048-bit RSA, signed by CA)
- `client.key/client.crt` - Client keypair (2048-bit RSA, signed by CA)

**Generation:** `python certs/generate_certs.py`

**Why 4096-bit for CA, 2048-bit for leaf certs?** The CA is the root of trust and should be stronger. Leaf certs are rotated more frequently, so 2048-bit is sufficient.

---

## 5.2 Mutual TLS (mTLS)

**What:** TLS where both sides authenticate. The server presents `server.crt` and the client presents `client.crt`. Both are verified against `ca.crt`.

**How it differs from normal HTTPS:**

| Normal HTTPS | Mutual TLS (mTLS) |
|---|---|
| Only server has a certificate | Both client and server have certificates |
| Client is anonymous | Client identity is cryptographically verified |
| Anyone can connect | Only authorized clients can connect |

---

## 5.3 ECDH (Elliptic Curve Diffie-Hellman)

**What:** A key agreement protocol where two parties each generate an ephemeral key pair on the P-256 curve and compute a shared secret.

**Why ECDH over RSA key transport?** ECDH provides **forward secrecy**. RSA key transport means the server's long-term key decrypts all sessions - if compromised, all past sessions are exposed.

---

## 5.4 Kyber-768 (ML-KEM)

**What:** A lattice-based Key Encapsulation Mechanism standardized by NIST as FIPS 203. Uses the hardness of the Module Learning With Errors (MLWE) problem, which is believed resistant to quantum attacks.

**KEM flow:**
1. Client generates Kyber keypair: `(pk, sk) = keygen()`
2. Server encapsulates: `(ciphertext, shared_secret) = enc(pk)`
3. Client decapsulates: `shared_secret = dec(ciphertext, sk)`

**Library:** `kyber-py` (pure Python, no C compilation needed)

---

## 5.5 HKDF (HMAC-based Key Derivation Function)

**What:** Extracts uniform random key material from potentially biased input. Defined in RFC 5869.

**Why needed?** Raw ECDH output is not uniformly random. HKDF's Extract-then-Expand ensures the derived AES key has full 256-bit entropy.

---

## 5.6 AES-256-GCM

**What:** Advanced Encryption Standard with 256-bit key in Galois/Counter Mode. An AEAD (Authenticated Encryption with Associated Data) cipher that provides both confidentiality and integrity in a single operation.

**Parameters:** 12-byte random nonce, `b"malware-sample"` as AAD.

---

## 5.7 HMAC-SHA256

**What:** Hash-based Message Authentication Code using SHA-256. Produces a 32-byte tag over the message that can only be verified by someone with the same key.

**What we HMAC:** `nonce || ciphertext` - covers both the IV and the encrypted data.

---

## 5.8 RSA-PSS Digital Signatures

**What:** RSA Probabilistic Signature Scheme. The client signs submission metadata to provide non-repudiation.

**Parameters:** MGF1 with SHA-256, maximum salt length.

---

# 6. Attack Demonstrations

## Attack 1: No Client Certificate (mTLS Bypass)

**Scenario:** An unauthorized user tries to connect without presenting a client certificate.

**Implementation** (`attack_demos.py` lines 36-58):
```python
r = requests.get(f"{SERVER}/health", verify=str(CERTS / "ca.crt"), timeout=5)
# NOTE: No cert=(...) parameter - client sends no certificate
```

**System response:** The TLS handshake fails at the SSL layer. The server's `ssl.CERT_REQUIRED` setting rejects the connection before any application code runs.

**Output:**
```
[BLOCKED] Connection rejected by server.
Error: SSLError
Detail: TLSV13_ALERT_CERTIFICATE_REQUIRED
```

**Property demonstrated:** Authentication (mTLS)

---

## Attack 2: Tampered Payload

**Scenario:** A man-in-the-middle intercepts the encrypted payload and flips a byte.

**Implementation** (`client/submit.py` lines 56-60):
```python
if tamper:
    raw = bytearray(b64d(enc["ciphertext"]))
    raw[0] ^= 0x01        # Flip one bit in first byte
    enc["ciphertext"] = b64e(bytes(raw))
```

**System response:** The server computes `HMAC(key, nonce + received_ciphertext)` and compares it to the received HMAC. Since the ciphertext was modified, the HMACs don't match.

**Output:**
```
HTTP 400: {"reason":"HMAC verification failed","status":"rejected"}
```

**Property demonstrated:** Integrity (HMAC-SHA256)

---

## Attack 3: Forged Signature (Impersonation)

**Scenario:** An attacker signs submission metadata with the WRONG RSA key (server.key instead of client.key), attempting to impersonate the legitimate client.

**Implementation** (`client/submit.py` line 53):
```python
key_path = CERTS / ("server.key" if forged_signature else "client.key")
signature = sign_metadata(canonical_json(metadata), str(key_path))
```

**System response:** The server verifies the signature against `client.crt`. Since the signature was made with `server.key`, the RSA-PSS verification fails.

**Output:**
```
HTTP 403: {"reason":"RSA-PSS signature verification failed","status":"rejected"}
```

**Property demonstrated:** Non-repudiation / Authentication (RSA-PSS)

---

## Attack 4: Modified Ciphertext with HMAC Bypass (Defence in Depth)

**Scenario:** A sophisticated attacker who somehow has the AES key modifies the ciphertext AND recomputes a valid HMAC. This bypasses the HMAC check. Can the system still detect the modification?

**Implementation** (`attack_demos.py` lines 136-146):
```python
# Modify ciphertext
raw = bytearray(b64d(enc["ciphertext"]))
raw[0] ^= 0xFF
modified_ct = bytes(raw)
enc["ciphertext"] = b64e(modified_ct)

# Recompute HMAC with correct key (bypasses HMAC check!)
new_hmac = hmac.new(aes_key, nonce + modified_ct, hashlib.sha256).digest()
enc["hmac"] = b64e(new_hmac)
```

**System response:** The HMAC check PASSES (it was recomputed correctly). But AES-GCM's built-in authentication tag detects the modification. GCM internally verifies integrity during decryption and raises `InvalidTag`.

**Output:**
```
HTTP 400: {"reason":"","status":"rejected"}
```

**Property demonstrated:** Defence in Depth - dual integrity protection (HMAC + GCM auth tag). Even bypassing one layer, the other catches the attack.

---

# 7. Threat Model

| Threat | Attack Vector | Mitigation | Demo |
|--------|--------------|------------|------|
| **Eavesdropping** | MITM intercepts binary in transit | AES-256-GCM + TLS 1.3 | Payload is encrypted |
| **Tampering** | Modify binary during transmission | HMAC-SHA256 + GCM auth tag | Attack 2 |
| **Impersonation** | Unauthorized client connects | Mutual TLS (mTLS) | Attack 1 |
| **Forgery** | Submit under someone else's identity | RSA-PSS digital signatures | Attack 3 |
| **Replay** | Re-send a previous valid submission | Ephemeral ECDH + random nonce + single-use sessions | Nonce uniqueness |
| **Quantum threat** | Future quantum computer breaks ECDH | Hybrid ECDH + Kyber-768 | Kyber KEM in key exchange |
| **Key compromise** | Stolen client private key | Certificate revocation by CA | Production: CRL/OCSP |
| **Session hijacking** | Steal session ID | 5-minute TTL + single-use consumption | Session expires |

---

# 8. Project Structure

```
isproject/
+-- certs/
|   +-- generate_certs.py      # Cross-platform cert generation (Python)
|   +-- generate_certs.sh      # Bash version (Linux/Mac)
|   +-- ca.key / ca.crt        # Root CA
|   +-- server.key / server.crt
|   +-- client.key / client.crt
+-- server/
|   +-- app.py                 # Flask HTTPS server with mTLS
+-- client/
|   +-- submit.py              # CLI client
+-- common/
|   +-- crypto_utils.py        # All crypto: ECDH, Kyber, AES-GCM, HMAC, RSA
+-- tests/
|   +-- test_crypto.py         # 17 unit tests
+-- samples/
|   +-- sample_pe.bin          # Sample PE binary (584 bytes, valid MZ header)
+-- logs/
|   +-- audit.log              # Server audit trail
+-- attack_demos.py            # 4 attack scenarios
+-- demo.py                    # End-to-end happy path
+-- requirements.txt           # Dependencies
+-- README.md                  # Project documentation
```

---

# 9. How to Run

```powershell
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate certificates
python certs/generate_certs.py

# 4. Start server (Terminal 1)
python -m server.app

# 5. Run demo (Terminal 2)
python demo.py

# 6. Run attack demos (Terminal 2)
python attack_demos.py

# 7. Run unit tests
python -m pytest tests/test_crypto.py -v
```

---

# 10. Viva Q&A Reference

| Question | Answer |
|----------|--------|
| Why AES-GCM over CBC? | GCM is AEAD - provides encryption + integrity in one pass. CBC needs separate MAC and is vulnerable to padding oracle attacks. |
| Why HMAC if GCM authenticates? | Defence in depth. HMAC is an independent application-layer check. Attack 4 proves both layers work independently. |
| Why ECDH over RSA key transport? | Forward secrecy. Ephemeral keys mean past sessions stay safe even if long-term keys leak. |
| Why Kyber-768? | NIST FIPS 203 standard. Lattice-based, resistant to Shor's Algorithm. 768 gives ~192-bit PQ security. |
| Why hybrid ECDH+Kyber? | Defence in depth. Key is safe if EITHER algorithm holds. Follows NIST migration guidance. |
| What is Zero Trust? | No implicit trust. Every request re-authenticated via mTLS. Sessions expire. No cookies. |
| What is forward secrecy? | Ephemeral ECDH keys per session. Past sessions protected even if long-term keys compromised later. |
| Why RSA-PSS over PKCS#1 v1.5? | PSS has formal security proof. PKCS#1 v1.5 vulnerable to Bleichenbacher forgery. |
| What if client key is stolen? | CA revokes the certificate. Production: CRL/OCSP checking. |
| Can attacker replay? | No. Each session uses ephemeral ECDH + fresh nonce. Sessions are single-use and expire in 5 minutes. |
| What is HKDF? | RFC 5869. Extracts uniform key from biased input. Binds key to protocol via `info` parameter. |
| Why `compare_digest`? | Prevents timing side-channel attacks. Constant-time comparison regardless of which byte differs. |
