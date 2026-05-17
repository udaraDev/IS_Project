from __future__ import annotations

from pathlib import Path
import requests
from client.submit import submit_binary

ROOT = Path(__file__).resolve().parent
CERTS = ROOT / "certs"
SAMPLE = str(ROOT / "samples" / "sample_pe.bin")
SERVER = "https://localhost:5000"


def attack_1_no_client_certificate():
    print("\n=== ATTACK 1: Connect without client certificate ===")
    try:
        r = requests.get(f"{SERVER}/health", verify=str(CERTS / "ca.crt"), timeout=5)
        print("Unexpected response:", r.status_code, r.text)
    except Exception as e:
        print("EXPECTED RESULT: mTLS rejected the connection.")
        print("Reason:", type(e).__name__, str(e)[:180])


def attack_2_tampered_payload():
    print("\n=== ATTACK 2: Tamper encrypted payload ===")
    submit_binary(SAMPLE, SERVER, tamper=True)
    print("EXPECTED RESULT: HMAC verification fails.")


def attack_3_forged_signature():
    print("\n=== ATTACK 3: Forged metadata signature ===")
    submit_binary(SAMPLE, SERVER, forged_signature=True)
    print("EXPECTED RESULT: RSA-PSS signature verification fails.")


def happy_path():
    print("\n=== HAPPY PATH: Authenticated encrypted malware submission ===")
    submit_binary(SAMPLE, SERVER)
    print("EXPECTED RESULT: Server accepts, decrypts, hashes, and logs sample.")


if __name__ == "__main__":
    print("Start server first: python server/app.py")
    attack_1_no_client_certificate()
    attack_2_tampered_payload()
    attack_3_forged_signature()
    happy_path()
