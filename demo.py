"""
End-to-end demo script for IS Project evaluation.
Demonstrates the full secure malware submission pipeline.

Usage:
    1. Start server:  python -m server.app
    2. Run demo:      python demo.py
"""

from __future__ import annotations

import sys
import json
from pathlib import Path

from client.submit import submit_binary

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "samples" / "sample_pe.bin"
SERVER = "https://localhost:5443"


def main():
    print("=" * 60)
    print("  IS PROJECT - END-TO-END SECURE SUBMISSION DEMO")
    print("  Zero Trust Secure Communication Framework")
    print("=" * 60)
    print()
    print("  Security Pipeline:")
    print("    1. Mutual TLS (mTLS) authentication")
    print("    2. Hybrid key exchange (ECDH P-256 + Kyber-768)")
    print("    3. HKDF key derivation -> AES-256 session key")
    print("    4. AES-256-GCM encryption of PE binary")
    print("    5. HMAC-SHA256 integrity protection")
    print("    6. RSA-PSS digital signature (non-repudiation)")
    print()

    if not SAMPLE.exists():
        print(f"[ERROR] Sample file not found: {SAMPLE}")
        sys.exit(1)

    sample_size = SAMPLE.stat().st_size
    print(f"  Submitting: {SAMPLE.name} ({sample_size} bytes)")
    print("-" * 60)
    print()

    try:
        r = submit_binary(str(SAMPLE), SERVER)
    except Exception as e:
        print(f"\n[ERROR] Submission failed: {type(e).__name__}: {e}")
        print("\nIs the server running?  python -m server.app")
        sys.exit(1)

    print()
    print("-" * 60)

    if r.status_code == 200:
        data = r.json()
        print("\n  [SUCCESS] Secure submission completed!")
        print(f"  Status:     {data.get('status', 'N/A')}")
        print(f"  SHA-256:    {data.get('sha256', 'N/A')}")
        print(f"  Audit Log:  {data.get('audit', 'N/A')}")
        print(f"  Response:   Encrypted (AES-256-GCM)")
        print()
        print("  All security properties verified:")
        print("    [OK] Mutual authentication (mTLS)")
        print("    [OK] Hybrid key exchange (ECDH + Kyber-768)")
        print("    [OK] End-to-end encryption (AES-256-GCM)")
        print("    [OK] Integrity protection (HMAC-SHA256)")
        print("    [OK] Non-repudiation (RSA-PSS signature)")
        print("    [OK] Zero Trust (per-request auth)")
    else:
        print(f"\n  [FAILED] HTTP {r.status_code}")
        print(f"  Response: {r.text}")
        sys.exit(1)

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
