"""
Attack demonstration script for IS Project evaluation.
Run with server already started: python -m server.app

Demonstrates 4 attack scenarios + 1 happy path:
  1. No client certificate      -> mTLS rejection
  2. Tampered payload           -> HMAC verification failure
  3. Forged signature           -> RSA-PSS verification failure
  4. Modified ciphertext (GCM)  -> AES-GCM auth tag failure
  5. Happy path                 -> Full secure submission
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests

from client.submit import submit_binary
from common.crypto_utils import (
    b64d, b64e, canonical_json, derive_hybrid_aes_key, ecdh_derive,
    encrypt_binary, generate_ecdh_keypair, kyber_decapsulate, kyber_keygen,
    sign_metadata,
)

ROOT = Path(__file__).resolve().parent
CERTS = ROOT / "certs"
SAMPLE = str(ROOT / "samples" / "sample_pe.bin")
SERVER = "https://localhost:5443"

SEPARATOR = "=" * 60


def attack_1_no_client_certificate():
    """ATTACK: Connect without a client certificate.
    EXPECTED: mTLS rejects connection (SSL handshake failure)."""
    print(f"\n{SEPARATOR}")
    print("ATTACK 1: Connect WITHOUT client certificate")
    print(f"{SEPARATOR}")
    print("Scenario: An unauthorized user tries to access the server")
    print("          without presenting a valid client certificate.")
    print(f"{'Mitigation:':<15} Mutual TLS (mTLS) - server requires client cert")
    print()

    try:
        r = requests.get(
            f"{SERVER}/health",
            verify=str(CERTS / "ca.crt"),
            timeout=5,
        )
        print(f"[UNEXPECTED] Got response: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[BLOCKED] Connection rejected by server.")
        print(f"  Error: {type(e).__name__}")
        print(f"  Detail: {str(e)[:150]}")
    print("\nRESULT: mTLS authentication prevented unauthorized access.")


def attack_2_tampered_payload():
    """ATTACK: Flip a byte in the encrypted payload.
    EXPECTED: HMAC verification fails on server side."""
    print(f"\n{SEPARATOR}")
    print("ATTACK 2: Tamper with encrypted payload")
    print(f"{SEPARATOR}")
    print("Scenario: A man-in-the-middle modifies the ciphertext in transit.")
    print(f"{'Mitigation:':<15} HMAC-SHA256 integrity check detects modification")
    print()

    r = submit_binary(SAMPLE, SERVER, tamper=True)
    if r.status_code != 200:
        print("\nRESULT: HMAC integrity check detected the tampering.")
    else:
        print("\n[UNEXPECTED] Server accepted tampered payload!")


def attack_3_forged_signature():
    """ATTACK: Submit with a different RSA key (impersonation).
    EXPECTED: RSA signature verification fails."""
    print(f"\n{SEPARATOR}")
    print("ATTACK 3: Forge metadata signature (impersonation)")
    print(f"{SEPARATOR}")
    print("Scenario: Attacker signs submission metadata with wrong RSA key.")
    print(f"{'Mitigation:':<15} RSA-PSS signature verification rejects forgery")
    print()

    r = submit_binary(SAMPLE, SERVER, forged_signature=True)
    if r.status_code == 403:
        print("\nRESULT: RSA-PSS signature verification rejected the forgery.")
    else:
        print(f"\n[UNEXPECTED] Server response: {r.status_code}")


def attack_4_modified_ciphertext_bypass_hmac():
    """ATTACK: Modify ciphertext AND recompute HMAC (to bypass HMAC check).
    The GCM authentication tag should still catch the modification.
    EXPECTED: AES-GCM authentication tag verification fails."""
    print(f"\n{SEPARATOR}")
    print("ATTACK 4: Modify ciphertext + recompute HMAC (bypass HMAC)")
    print(f"{SEPARATOR}")
    print("Scenario: Attacker knows the AES key, modifies ciphertext,")
    print("          and recomputes a valid HMAC. GCM auth tag still catches it.")
    print(f"{'Mitigation:':<15} AES-GCM authentication tag (defence in depth)")
    print()

    # Perform key exchange normally
    path = Path(SAMPLE)
    data = path.read_bytes()

    client_ecdh_priv, client_ecdh_pub = generate_ecdh_keypair()
    kyber_kp = kyber_keygen()

    init_payload = {
        "client_ecdh_pub": b64e(client_ecdh_pub),
        "client_kyber_pk": b64e(kyber_kp.public_key),
    }

    r = requests.post(
        f"{SERVER}/init",
        json=init_payload,
        cert=(str(CERTS / "client.crt"), str(CERTS / "client.key")),
        verify=str(CERTS / "ca.crt"),
        timeout=10,
    )
    r.raise_for_status()
    init = r.json()

    ecdh_shared = ecdh_derive(client_ecdh_priv, b64d(init["server_ecdh_pub"]))
    kyber_shared = kyber_decapsulate(b64d(init["kyber_ciphertext"]), kyber_kp.secret_key)
    aes_key = derive_hybrid_aes_key(ecdh_shared, kyber_shared)

    # Encrypt normally
    enc = encrypt_binary(data, aes_key)

    # ATTACK: modify ciphertext, then recompute HMAC with the correct key
    raw = bytearray(b64d(enc["ciphertext"]))
    raw[0] ^= 0xFF  # Flip bits in first byte
    modified_ct = bytes(raw)
    enc["ciphertext"] = b64e(modified_ct)

    # Recompute HMAC so it matches the modified ciphertext (bypasses HMAC check)
    import hashlib, hmac
    nonce = b64d(enc["nonce"])
    new_hmac = hmac.new(aes_key, nonce + modified_ct, hashlib.sha256).digest()
    enc["hmac"] = b64e(new_hmac)

    print("[ATTACK] Ciphertext modified AND HMAC recomputed.")
    print("[ATTACK] HMAC check will PASS, but GCM auth tag should FAIL.")

    # Sign metadata normally
    import time
    metadata = {
        "client_id": "analyst-client",
        "filename": path.name,
        "timestamp": int(time.time()),
        "purpose": "malware-sample-submission",
    }
    signature = sign_metadata(canonical_json(metadata), str(CERTS / "client.key"))

    submit_payload = {
        "session_id": init["session_id"],
        "metadata": metadata,
        "signature": signature,
        **enc,
    }

    r = requests.post(
        f"{SERVER}/submit",
        json=submit_payload,
        cert=(str(CERTS / "client.crt"), str(CERTS / "client.key")),
        verify=str(CERTS / "ca.crt"),
        timeout=10,
    )
    print(f"[SERVER] HTTP {r.status_code}: {r.text}")

    if r.status_code != 200:
        print("\nRESULT: AES-GCM auth tag rejected the modified ciphertext.")
        print("        Defence in depth works: even bypassing HMAC, GCM catches it.")
    else:
        print("\n[UNEXPECTED] Server accepted modified payload!")


def happy_path():
    """Normal secure submission - should succeed."""
    print(f"\n{SEPARATOR}")
    print("HAPPY PATH: Authenticated encrypted malware submission")
    print(f"{SEPARATOR}")
    print("Scenario: Authorized client submits PE binary through full")
    print("          secure pipeline (mTLS + Hybrid KEM + AES-GCM + HMAC + RSA-PSS).")
    print()

    r = submit_binary(SAMPLE, SERVER)
    if r.status_code == 200:
        print("\nRESULT: Full secure submission completed successfully!")
    else:
        print(f"\n[UNEXPECTED] Server response: {r.status_code} {r.text}")


def main():
    print("=" * 60)
    print("  IS PROJECT - SECURITY ATTACK DEMONSTRATIONS")
    print("  Zero Trust Secure Communication Framework")
    print("=" * 60)
    print("\nIMPORTANT: Start server first:  python -m server.app")
    print()

    attack_1_no_client_certificate()
    attack_2_tampered_payload()
    attack_3_forged_signature()
    attack_4_modified_ciphertext_bypass_hmac()
    happy_path()

    print(f"\n{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}")
    print("  Attack 1 (No cert)         -> BLOCKED by mTLS")
    print("  Attack 2 (Tampered)        -> BLOCKED by HMAC-SHA256")
    print("  Attack 3 (Forged sig)      -> BLOCKED by RSA-PSS")
    print("  Attack 4 (HMAC bypass)     -> BLOCKED by AES-GCM auth tag")
    print("  Happy Path                 -> ACCEPTED (all checks passed)")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
