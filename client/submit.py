from __future__ import annotations

import argparse
import time
from pathlib import Path
import requests

from common.crypto_utils import (
    b64d, b64e, canonical_json, derive_hybrid_aes_key, ecdh_derive,
    encrypt_binary, generate_ecdh_keypair, kyber_decapsulate, kyber_keygen,
    sign_metadata,
)

ROOT = Path(__file__).resolve().parents[1]
CERTS = ROOT / "certs"


def submit_binary(binary_path: str, server: str, tamper: bool = False, forged_signature: bool = False):
    path = Path(binary_path)
    data = path.read_bytes()

    client_ecdh_priv, client_ecdh_pub = generate_ecdh_keypair()
    kyber_kp = kyber_keygen()
    print(f"[1] PQ KEM backend: {kyber_kp.backend}")

    init_payload = {
        "client_ecdh_pub": b64e(client_ecdh_pub),
        "client_kyber_pk": b64e(kyber_kp.public_key),
    }
    print("[2] Starting mTLS + hybrid ECDH/Kyber key exchange...")
    r = requests.post(
        f"{server}/init",
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
    print("[3] AES-256 session key derived using HKDF(ECDH || Kyber).")

    enc = encrypt_binary(data, aes_key)
    metadata = {
        "client_id": "analyst-client",
        "filename": path.name,
        "timestamp": int(time.time()),
        "purpose": "malware-sample-submission",
    }
    key_path = CERTS / ("server.key" if forged_signature else "client.key")
    signature = sign_metadata(canonical_json(metadata), str(key_path))

    if tamper:
        raw = bytearray(b64d(enc["ciphertext"]))
        raw[0] ^= 0x01
        enc["ciphertext"] = b64e(bytes(raw))
        print("[ATTACK] Ciphertext modified after encryption.")

    submit_payload = {
        "session_id": init["session_id"],
        "metadata": metadata,
        "signature": signature,
        **enc,
    }
    print("[4] Submitting encrypted payload + HMAC + RSA-PSS signature...")
    r = requests.post(
        f"{server}/submit",
        json=submit_payload,
        cert=(str(CERTS / "client.crt"), str(CERTS / "client.key")),
        verify=str(CERTS / "ca.crt"),
        timeout=10,
    )
    print(f"[5] Server response HTTP {r.status_code}: {r.text}")
    return r


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure malware sample submission client")
    parser.add_argument("--binary", default=str(ROOT / "samples" / "sample_pe.bin"))
    parser.add_argument("--server", default="https://localhost:5000")
    parser.add_argument("--tamper", action="store_true")
    parser.add_argument("--forged-signature", action="store_true")
    args = parser.parse_args()
    submit_binary(args.binary, args.server, args.tamper, args.forged_signature)
