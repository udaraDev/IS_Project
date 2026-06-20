# Zero Trust Secure Communication Framework for Malware Sample Submission

## Mutual Authentication + AES-256-GCM + Hybrid ECDH/Kyber-768 Post-Quantum Security

---

# 1. Project Overview

## Project Title

**Zero Trust Secure Communication Framework for Malware Sample Submission Using Mutual Authentication, End-to-End Encryption and Post-Quantum Readiness**

---

# 2. Main Goal of the Project

This project demonstrates a secure malware submission framework where a client securely submits a malware binary to a server using:

* Mutual TLS (mTLS)
* AES-256-GCM encryption
* HMAC integrity protection
* RSA-PSS digital signatures
* Hybrid ECDH + Kyber-768 post-quantum key exchange

The system protects malware samples against:

* Unauthorized access
* Tampering
* Impersonation
* Replay attacks
* Future quantum threats

---

# 3. Core Security Pillars

| Pillar                 | Implementation          |
| ---------------------- | ----------------------- |
| Mutual Authentication  | Mutual TLS (mTLS)       |
| End-to-End Encryption  | AES-256-GCM             |
| Post-Quantum Readiness | Hybrid ECDH + Kyber-768 |

Additional security mechanisms:

| Security Property       | Mechanism                            |
| ----------------------- | ------------------------------------ |
| Authentication          | mTLS                                 |
| Confidentiality         | AES-256-GCM                          |
| Integrity               | HMAC-SHA256 + GCM Tag                |
| Non-Repudiation         | RSA-PSS                              |
| Forward Secrecy         | Ephemeral ECDH                       |
| Post-Quantum Protection | Kyber-768                            |
| Zero Trust              | Per-request certificate verification |

---

# 4. System Architecture

```text
CLIENT
│
├── Load malware binary
├── mTLS authentication
├── ECDH + Kyber key exchange
├── HKDF session key derivation
├── AES-256-GCM encryption
├── HMAC integrity generation
├── RSA-PSS metadata signing
│
▼
SECURE CHANNEL
(TLS 1.3 + Hybrid Encryption)
│
▼
SERVER
│
├── Verify client certificate
├── Verify HMAC
├── Verify RSA signature
├── Derive same AES key
├── Decrypt malware sample
├── Generate SHA256 hash
├── Audit logging
│
▼
Encrypted response returned
```

---

# 5. Full Communication Flow

## Step 1 — Mutual TLS Authentication

Both client and server authenticate each other using X.509 certificates.

Purpose:

* Prevent unauthorized access
* Prevent impersonation
* Enforce Zero Trust authentication

---

## Step 2 — Hybrid Key Exchange

The client and server perform:

* ECDH key exchange
* Kyber-768 post-quantum key exchange

Both shared secrets are combined.

```text
ECDH shared secret + Kyber shared secret
```

---

## Step 3 — HKDF Key Derivation

The combined secret is passed through HKDF.

```text
HKDF(ECDH || Kyber)
```

This generates the AES-256 session key.

---

## Step 4 — AES-256-GCM Encryption

The malware sample is encrypted using AES-256-GCM.

Purpose:

* Confidentiality
* Authenticated encryption

---

## Step 5 — HMAC Integrity Protection

An HMAC-SHA256 value is generated over:

```text
nonce + ciphertext
```

Purpose:

* Detect tampering
* Defence in depth

---

## Step 6 — RSA-PSS Digital Signature

The client signs metadata using RSA-PSS.

Purpose:

* Non-repudiation
* Prevent forged submissions

---

## Step 7 — Server Verification

The server:

* Verifies HMAC
* Verifies RSA signature
* Derives same AES key
* Decrypts malware sample
* Generates SHA256 hash
* Logs submission

---

# 6. Why Each Technology Was Used

## Why Mutual TLS?

Unlike normal TLS where only the server is authenticated, mTLS authenticates both the client and server.

Benefits:

* Prevents unauthorized clients
* Prevents impersonation
* Implements Zero Trust

---

## Why AES-256-GCM?

AES-GCM is an authenticated encryption mode.

Benefits:

* Encryption + integrity in one operation
* Resistant to padding oracle attacks
* Fast and secure

Why not CBC?

* CBC requires separate MAC
* CBC vulnerable to padding oracle attacks

---

## Why HMAC if GCM already authenticates?

Purpose:

* Defence in depth
* Independent integrity verification
* Application-layer protection

---

## Why ECDH?

ECDH provides:

* Secure key exchange
* Forward secrecy

Even if long-term keys are compromised later, previous session keys remain protected.

---

## Why Kyber-768?

Kyber-768 is:

* A lattice-based post-quantum ML-KEM
* Standardized by NIST FIPS 203
* Resistant to known quantum attacks

---

## Why Hybrid ECDH + Kyber?

The hybrid approach provides defence in depth.

| Scenario     | Protection           |
| ------------ | -------------------- |
| ECDH broken  | Kyber still protects |
| Kyber broken | ECDH still protects  |

Important concept:

> The session key remains secure as long as at least one algorithm remains secure.

---

# 7. Threat Model

## Threat 1 — Eavesdropping

### Attack

Attacker intercepts malware sample.

### Mitigation

* TLS 1.3
* AES-256-GCM

---

## Threat 2 — Tampering

### Attack

Attacker modifies ciphertext.

### Mitigation

* HMAC-SHA256
* AES-GCM authentication tag

---

## Threat 3 — Impersonation

### Attack

Unauthorized client pretends to be legitimate.

### Mitigation

* Mutual TLS certificates

---

## Threat 4 — Forged Submission

### Attack

Attacker submits malware using fake identity.

### Mitigation

* RSA-PSS digital signatures

---

## Threat 5 — Replay Attack

### Attack

Attacker resends previous encrypted payload.

### Mitigation

* Ephemeral ECDH
* Random nonce

---

## Threat 6 — Quantum Threat

### Attack

Future quantum computers break RSA/ECC.

### Mitigation

* Kyber-768 post-quantum cryptography

---

# 8. Project Structure

```text
isproject_full/
│
├── certs/
│   ├── generate_certs.sh
│   ├── ca.crt
│   ├── ca.key
│   ├── client.crt
│   ├── client.key
│   ├── server.crt
│   └── server.key
│
├── client/
│   └── submit.py
│
├── server/
│   └── app.py
│
├── common/
│   └── crypto_utils.py
│
├── tests/
│   └── test_crypto.py
│
├── logs/
│   └── audit.log
│
├── samples/
│   └── sample_pe.bin
│
├── attack_demos.py
├── demo.py
├── requirements.txt
└── README.md
```

---

# 9. Installation Guide

## Step 1 — Extract Project

Extract:

```text
isproject_full.zip
```

---

## Step 2 — Open VS Code

Open the extracted project folder.

---

## Step 3 — Create Virtual Environment

```powershell
python -m venv venv
```

Activate:

```powershell
venv\Scripts\activate
```

---

## Step 4 — Install Requirements

```powershell
pip install -r requirements.txt
```

---

## Step 5 — Generate Certificates

Using Git Bash:

```bash
bash certs/generate_certs.sh
```

---

# 10. Running the Project

## Start Secure Server

```powershell
python -m server.app
```

Expected:

```text
Running on https://127.0.0.1:5000
```

---

## Run Happy Path Demo

Open second terminal:

```powershell
venv\Scripts\activate
python demo.py
```

Expected successful output:

```text
HTTP 200
status: accepted
```

---

# 11. Running Attack Demonstrations

Open another terminal:

```powershell
venv\Scripts\activate
python attack_demos.py
```

---

## Attack 1 — No Client Certificate

Expected:

```text
SSL handshake failure
```

Meaning:

* Unauthorized clients rejected

---

## Attack 2 — Tampered Payload

Expected:

```text
HMAC verification failed
```

Meaning:

* Integrity protection works

---

## Attack 3 — Forged Signature

Expected:

```text
RSA-PSS signature verification failed
```

Meaning:

* Forged submissions rejected

---

## Happy Path

Expected:

```text
HTTP 200
status: accepted
```

Meaning:

* Full secure workflow successful

---

# 12. Evaluation Demonstration Flow

## Step 1 — Start Server

```powershell
python -m server.app
```

---

## Step 2 — Show Successful Submission

```powershell
python demo.py
```

Explain:

* Hybrid key exchange
* AES encryption
* HMAC integrity
* RSA signature
* SHA256 hash generation

---

## Step 3 — Show Attack Demos

```powershell
python attack_demos.py
```

Explain:

* Unauthorized client rejection
* Tampering detection
* Forged signature rejection

---

# 13. Post-Quantum Security Explanation

## Current Problem

Traditional cryptography:

* RSA
* ECC
* ECDH

can be broken by quantum computers using:

```text
Shor’s Algorithm
```

---

## Solution

This project integrates:

```text
Kyber-768 (ML-KEM)
```

Kyber is:

* Lattice-based cryptography
* Standardized by NIST FIPS 203
* Resistant to known quantum attacks

---

## Hybrid Security Model

```text
ECDH shared secret
+
Kyber shared secret
↓
HKDF
↓
AES-256 session key
```

Important concept:

> The session key remains secure as long as at least one algorithm remains secure.

---

# 14. Zero Trust Concept

The project follows Zero Trust principles.

Meaning:

* No implicit trust
* Every request authenticated
* Every client verified
* No unauthenticated communication allowed

---

# 15. FYP Integration

This project secures the malware submission pipeline of the malware static analysis FYP.

Workflow:

```text
User submits malware
↓
Secure communication framework
↓
Malware analysis server
↓
CFG extraction + ML/GNN analysis
↓
Secure response returned
```

---

# 16. Important Viva Questions and Answers

## Q: Why AES-GCM instead of CBC?

Answer:

AES-GCM provides authenticated encryption and avoids padding oracle vulnerabilities associated with CBC mode.

---

## Q: Why HMAC if GCM already authenticates?

Answer:

HMAC provides defence in depth through an independent application-layer integrity check.

---

## Q: Why use hybrid ECDH + Kyber?

Answer:

The session key remains secure as long as either ECDH or Kyber remains secure.

---

## Q: What is Kyber?

Answer:

Kyber-768 is a lattice-based post-quantum ML-KEM standardized by NIST FIPS 203.

---

## Q: How is this Zero Trust?

Answer:

Every request requires certificate-based authentication with no implicit trust.

---

## Q: What is forward secrecy?

Answer:

Ephemeral ECDH ensures previous session keys remain protected even if long-term keys are compromised.

---

# 17. Final Conclusion

This project successfully demonstrates a Zero Trust secure malware submission framework integrating:

* Mutual TLS authentication
* Hybrid ECDH + Kyber-768 key exchange
* HKDF key derivation
* AES-256-GCM encryption
* HMAC-SHA256 integrity protection
* RSA-PSS digital signatures
* Attack mitigation demonstrations
* Post-quantum readiness

The system securely protects malware sample communication against both current and future threats.
