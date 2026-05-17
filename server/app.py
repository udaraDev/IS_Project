from __future__ import annotations

import os
import ssl
import time
import uuid
from pathlib import Path
from flask import Flask, jsonify, request

from common.crypto_utils import (
    b64d, b64e, canonical_json, decrypt_binary, derive_hybrid_aes_key,
    ecdh_derive, encrypt_binary, generate_ecdh_keypair, kyber_encapsulate,
    sha256_hex, verify_signature,
)

ROOT = Path(__file__).resolve().parents[1]
CERTS = ROOT / "certs"
LOGS = ROOT / "logs"
LOGS.mkdir(exist_ok=True)

app = Flask(__name__)

# Session storage with timestamps for TTL-based cleanup
SESSION_TTL = 300  # 5 minutes
SESSIONS: dict[str, dict] = {}  # session_id -> {"key": bytes, "created": float}


def _cleanup_expired_sessions():
    """Remove sessions older than SESSION_TTL (Zero Trust: no persistent trust)."""
    now = time.time()
    expired = [sid for sid, s in SESSIONS.items() if now - s["created"] > SESSION_TTL]
    for sid in expired:
        del SESSIONS[sid]


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "security": "mTLS required by server SSL context",
        "message": "Authenticated client reached secure server"
    })


@app.route("/init", methods=["POST"])
def init_key_exchange():
    body = request.get_json(force=True)
    client_ecdh_pub = b64d(body["client_ecdh_pub"])
    client_kyber_pk = b64d(body["client_kyber_pk"])

    server_ecdh_priv, server_ecdh_pub = generate_ecdh_keypair()
    ecdh_shared = ecdh_derive(server_ecdh_priv, client_ecdh_pub)
    kyber_ct, kyber_shared = kyber_encapsulate(client_kyber_pk)
    aes_key = derive_hybrid_aes_key(ecdh_shared, kyber_shared)

    session_id = str(uuid.uuid4())
    _cleanup_expired_sessions()
    SESSIONS[session_id] = {"key": aes_key, "created": time.time()}
    return jsonify({
        "session_id": session_id,
        "server_ecdh_pub": b64e(server_ecdh_pub),
        "kyber_ciphertext": b64e(kyber_ct),
        "note": "Hybrid ECDH + Kyber shared key established"
    })


@app.route("/submit", methods=["POST"])
def submit():
    body = request.get_json(force=True)
    session_id = body.get("session_id")
    if session_id not in SESSIONS:
        return jsonify({"status": "error", "reason": "unknown or expired session"}), 400

    session = SESSIONS.pop(session_id)

    # Check session TTL (Zero Trust: time-limited trust)
    if time.time() - session["created"] > SESSION_TTL:
        return jsonify({"status": "error", "reason": "session expired"}), 400

    aes_key = session["key"]

    metadata = body["metadata"]
    metadata_bytes = canonical_json(metadata)

    # NOTE: In production, the client certificate should be extracted from the
    # TLS handshake via request.environ['SSL_CLIENT_CERT'] (requires a proper
    # WSGI server like Gunicorn with SSL). For this demo, Flask's built-in
    # server doesn't expose client certs, so we read from disk.
    with open(CERTS / "client.crt", "rb") as f:
        client_cert_pem = f.read()

    if not verify_signature(metadata_bytes, body["signature"], client_cert_pem):
        return jsonify({"status": "rejected", "reason": "RSA-PSS signature verification failed"}), 403

    try:
        plaintext = decrypt_binary(body["nonce"], body["ciphertext"], body["hmac"], aes_key)
    except Exception as e:
        return jsonify({"status": "rejected", "reason": str(e)}), 400

    digest = sha256_hex(plaintext)
    audit_line = f"{time.ctime()} | client={metadata.get('client_id')} | file={metadata.get('filename')} | sha256={digest}\n"
    with open(LOGS / "audit.log", "a", encoding="utf-8") as f:
        f.write(audit_line)

    response_plain = f"ACCEPTED: {metadata.get('filename')} sha256={digest}".encode()
    encrypted_response = encrypt_binary(response_plain, aes_key, aad=b"server-response")
    return jsonify({
        "status": "accepted",
        "sha256": digest,
        "encrypted_response": encrypted_response,
        "audit": "logs/audit.log updated"
    })


def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / "server.crt"), str(CERTS / "server.key"))
    ctx.load_verify_locations(str(CERTS / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    return ctx


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure mTLS server")
    parser.add_argument("--port", type=int, default=5443, help="Port to listen on (default: 5443)")
    args = parser.parse_args()

    if not (CERTS / "server.crt").exists():
        raise SystemExit("Run: python certs/generate_certs.py first")
    print(f"Starting mTLS server on https://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, ssl_context=create_ssl_context(), debug=False)
