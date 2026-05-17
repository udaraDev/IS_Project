"""
Crypto utilities for the IS evaluation project.
Educational prototype: kyber-py is used for PQ-readiness demonstration, not production cryptography.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import warnings
from dataclasses import dataclass
from typing import Any, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)


# =========================================================
# Base64 Helpers
# =========================================================

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# =========================================================
# ECDH
# =========================================================

def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())

    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key, public_key_bytes


def ecdh_derive(private_key, peer_public_key_bytes: bytes) -> bytes:
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)

    return private_key.exchange(ec.ECDH(), peer_public_key)


# =========================================================
# Kyber / ML-KEM Compatibility Layer
# =========================================================

@dataclass
class KyberKeypair:
    public_key: bytes
    secret_key: bytes
    backend: str


def _load_kyber768():
    candidates = []

    try:
        from kyber_py.kyber import Kyber768
        candidates.append(Kyber768)
    except Exception:
        pass

    try:
        from kyber_py.kyber.default_parameters import Kyber768
        candidates.append(Kyber768)
    except Exception:
        pass

    try:
        from kyber import Kyber768
        candidates.append(Kyber768)
    except Exception:
        pass

    return candidates[0] if candidates else None


_KYBER = _load_kyber768()

_TOY_STORE: dict[bytes, bytes] = {}


def kyber_keygen() -> KyberKeypair:
    if _KYBER is not None:
        pk, sk = _KYBER.keygen()
        return KyberKeypair(
            pk,
            sk,
            "kyber-py Kyber768/ML-KEM demo"
        )

    # fallback demo mode
    sk = os.urandom(32)
    pk = hashlib.sha256(b"toy-pk" + sk).digest()

    _TOY_STORE[pk] = sk

    warnings.warn(
        "kyber-py not installed; using NON-SECURE toy fallback."
    )

    return KyberKeypair(
        pk,
        sk,
        "TOY-FALLBACK-NOT-PQ"
    )


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """
    Returns:
        ciphertext, shared_secret
    """

    if _KYBER is not None:

        for method_name in ("encaps", "encapsulate", "enc"):

            if hasattr(_KYBER, method_name):

                out = getattr(_KYBER, method_name)(public_key)

                a, b = out[0], out[1]

                # Some versions:
                # shared_secret, ciphertext

                # Other versions:
                # ciphertext, shared_secret

                if len(a) == 32 and len(b) > 32:
                    shared_secret = a
                    ciphertext = b
                else:
                    ciphertext = a
                    shared_secret = b

                return ciphertext, shared_secret

        raise RuntimeError(
            "Unsupported kyber-py API"
        )

    # fallback demo mode
    shared_secret = os.urandom(32)

    ciphertext = (
        b"TOYCT"
        + hashlib.sha256(public_key + shared_secret).digest()
        + shared_secret
    )

    _TOY_STORE[ciphertext] = shared_secret

    return ciphertext, shared_secret


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:

    if _KYBER is not None:

        for method_name in ("decaps", "decapsulate", "dec"):

            if hasattr(_KYBER, method_name):

                method = getattr(_KYBER, method_name)

                # Newer API
                try:
                    return method(secret_key, ciphertext)
                except Exception:
                    pass

                # Older API
                try:
                    return method(ciphertext, secret_key)
                except Exception:
                    pass

        raise RuntimeError(
            "Unsupported kyber-py API or decapsulation failed"
        )

    # fallback demo mode
    if ciphertext in _TOY_STORE:
        return _TOY_STORE[ciphertext]

    if ciphertext.startswith(b"TOYCT"):
        return ciphertext[-32:]

    raise ValueError("Toy KEM decapsulation failed")


# =========================================================
# HKDF Hybrid Key Derivation
# =========================================================

def derive_hybrid_aes_key(
    ecdh_shared: bytes,
    kyber_shared: bytes,
    context: bytes = b"malware-submission-hybrid-v1",
) -> bytes:

    combined = ecdh_shared + kyber_shared

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(combined)


# =========================================================
# AES-GCM + HMAC
# =========================================================

def encrypt_binary(
    binary_data: bytes,
    aes_key: bytes,
    aad: bytes = b"malware-sample",
) -> dict[str, str]:

    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        binary_data,
        aad,
    )

    mac = hmac.new(
        aes_key,
        nonce + ciphertext,
        hashlib.sha256,
    ).digest()

    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "hmac": b64e(mac),
    }


def decrypt_binary(
    nonce_b64: str,
    ciphertext_b64: str,
    hmac_b64: str,
    aes_key: bytes,
    aad: bytes = b"malware-sample",
) -> bytes:

    nonce = b64d(nonce_b64)

    ciphertext = b64d(ciphertext_b64)

    received_mac = b64d(hmac_b64)

    expected_mac = hmac.new(
        aes_key,
        nonce + ciphertext,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(
        received_mac,
        expected_mac,
    ):
        raise ValueError(
            "HMAC verification failed"
        )

    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        aad,
    )


# =========================================================
# RSA-PSS Signatures
# =========================================================

def sign_metadata(
    metadata: bytes,
    private_key_path: str,
) -> str:

    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(
            f.read(),
            password=None,
        )

    signature = private_key.sign(
        metadata,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return b64e(signature)


def verify_signature(
    metadata: bytes,
    signature_b64: str,
    public_key_pem: bytes,
) -> bool:

    try:

        # If certificate passed
        if b"BEGIN CERTIFICATE" in public_key_pem:

            cert = x509.load_pem_x509_certificate(
                public_key_pem
            )

            public_key = cert.public_key()

        else:
            public_key = load_pem_public_key(
                public_key_pem
            )

        public_key.verify(
            b64d(signature_b64),
            metadata,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except Exception:
        return False


# =========================================================
# SHA256
# =========================================================

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()