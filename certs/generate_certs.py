"""
Generate all PKI certificates for the IS project.
Cross-platform Python script (works on Windows without bash/WSL).
"""

import subprocess
import os
import sys
from pathlib import Path

CERTS_DIR = Path(__file__).resolve().parent
OPENSSL = None

# Find OpenSSL
for candidate in [
    "openssl",
    r"C:\Program Files\Git\usr\bin\openssl.exe",
    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
]:
    try:
        result = subprocess.run(
            [candidate, "version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            OPENSSL = candidate
            print(f"[OK] Using: {candidate} ({result.stdout.strip()})")
            break
    except Exception:
        continue

if OPENSSL is None:
    print("ERROR: OpenSSL not found. Install Git for Windows or OpenSSL.")
    sys.exit(1)


def run(cmd: str):
    """Run an OpenSSL command."""
    full = cmd.replace("openssl", f'"{OPENSSL}"', 1)
    print(f"  > {cmd}")
    result = subprocess.run(
        full, shell=True, capture_output=True, text=True,
        cwd=str(CERTS_DIR),
    )
    if result.returncode != 0:
        print(f"  FAILED: {result.stderr.strip()}")
        sys.exit(1)


def main():
    os.chdir(CERTS_DIR)

    # Clean old files
    for ext in ("*.key", "*.crt", "*.csr", "*.srl", "*.ext"):
        for f in CERTS_DIR.glob(ext):
            f.unlink()

    print("\n[1/3] Creating Root CA (4096-bit RSA)...")
    run('openssl genrsa -out ca.key 4096')
    run('openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt '
        '-subj "/CN=MalwareAnalysisCA/O=ISProject/C=LK"')

    print("\n[2/3] Creating Server certificate...")
    run('openssl genrsa -out server.key 2048')
    run('openssl req -new -key server.key -out server.csr '
        '-subj "/CN=localhost/O=ISProject/C=LK"')

    # Write server extensions file
    (CERTS_DIR / "server.ext").write_text(
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = @alt_names\n"
        "[alt_names]\n"
        "DNS.1 = localhost\n"
        "IP.1 = 127.0.0.1\n"
    )
    run('openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial '
        '-out server.crt -days 365 -sha256 -extfile server.ext')

    print("\n[3/3] Creating Client certificate...")
    run('openssl genrsa -out client.key 2048')
    run('openssl req -new -key client.key -out client.csr '
        '-subj "/CN=analyst-client/O=ISProject/C=LK"')

    (CERTS_DIR / "client.ext").write_text(
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = clientAuth\n"
    )
    run('openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial '
        '-out client.crt -days 365 -sha256 -extfile client.ext')

    # Cleanup temporary files
    for ext in ("*.csr", "*.ext"):
        for f in CERTS_DIR.glob(ext):
            f.unlink()

    print("\n[OK] All certificates generated successfully in certs/")
    print("   ca.key, ca.crt")
    print("   server.key, server.crt")
    print("   client.key, client.crt")


if __name__ == "__main__":
    main()
