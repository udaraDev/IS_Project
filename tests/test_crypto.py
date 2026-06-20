"""
Unit tests for IS Project crypto utilities.
Run: pytest tests/test_crypto.py -v
"""

import os
import pytest

from common.crypto_utils import (
    b64d, b64e,
    generate_ecdh_keypair, ecdh_derive,
    kyber_keygen, kyber_encapsulate, kyber_decapsulate,
    derive_hybrid_aes_key,
    encrypt_binary, decrypt_binary,
    sign_metadata, verify_signature,
    sha256_hex,
    canonical_json,
)


# =========================================================
# ECDH Tests
# =========================================================

class TestECDH:
    def test_key_agreement(self):
        """Both parties derive the same ECDH shared secret."""
        client_priv, client_pub = generate_ecdh_keypair()
        server_priv, server_pub = generate_ecdh_keypair()

        client_shared = ecdh_derive(client_priv, server_pub)
        server_shared = ecdh_derive(server_priv, client_pub)

        assert client_shared == server_shared
        assert len(client_shared) == 32  # P-256 produces 32-byte shared secret


# =========================================================
# Kyber-768 Tests
# =========================================================

class TestKyber:
    def test_keygen_returns_keypair(self):
        """Kyber keygen produces public and secret keys."""
        kp = kyber_keygen()
        assert kp.public_key is not None
        assert kp.secret_key is not None
        assert len(kp.backend) > 0

    def test_encap_decap_roundtrip(self):
        """Kyber encapsulate -> decapsulate produces same shared secret."""
        kp = kyber_keygen()
        ciphertext, ss_sender = kyber_encapsulate(kp.public_key)
        ss_receiver = kyber_decapsulate(ciphertext, kp.secret_key)

        assert ss_sender == ss_receiver
        assert len(ss_sender) == 32  # Kyber-768 produces 32-byte shared secret


# =========================================================
# Hybrid Key Agreement Tests
# =========================================================

class TestHybridKeyAgreement:
    def test_full_hybrid_pipeline(self):
        """
        Full hybrid key exchange: client & server independently
        derive the same AES-256 key from ECDH + Kyber.
        """
        # Client generates ECDH + Kyber keypairs
        client_ecdh_priv, client_ecdh_pub = generate_ecdh_keypair()
        kyber_kp = kyber_keygen()

        # Server generates ECDH keypair + encapsulates to client's Kyber pubkey
        server_ecdh_priv, server_ecdh_pub = generate_ecdh_keypair()
        kyber_ct, kyber_shared_server = kyber_encapsulate(kyber_kp.public_key)

        # Server derives its AES key
        ecdh_shared_server = ecdh_derive(server_ecdh_priv, client_ecdh_pub)
        server_aes_key = derive_hybrid_aes_key(ecdh_shared_server, kyber_shared_server)

        # Client derives its AES key
        ecdh_shared_client = ecdh_derive(client_ecdh_priv, server_ecdh_pub)
        kyber_shared_client = kyber_decapsulate(kyber_ct, kyber_kp.secret_key)
        client_aes_key = derive_hybrid_aes_key(ecdh_shared_client, kyber_shared_client)

        # Both must agree
        assert server_aes_key == client_aes_key
        assert len(server_aes_key) == 32  # AES-256

    def test_different_kyber_keys_produce_different_aes_keys(self):
        """Different Kyber keypairs lead to different AES session keys."""
        client_ecdh_priv, client_ecdh_pub = generate_ecdh_keypair()
        server_ecdh_priv, server_ecdh_pub = generate_ecdh_keypair()

        ecdh_shared = ecdh_derive(client_ecdh_priv, server_ecdh_pub)

        kp1 = kyber_keygen()
        _, kyber_ss1 = kyber_encapsulate(kp1.public_key)
        key1 = derive_hybrid_aes_key(ecdh_shared, kyber_ss1)

        kp2 = kyber_keygen()
        _, kyber_ss2 = kyber_encapsulate(kp2.public_key)
        key2 = derive_hybrid_aes_key(ecdh_shared, kyber_ss2)

        assert key1 != key2


# =========================================================
# AES-GCM + HMAC Tests
# =========================================================

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        """Binary survives encrypt -> decrypt."""
        key = os.urandom(32)
        original = b"MZ\x90\x00" + os.urandom(256)  # Fake PE header
        enc = encrypt_binary(original, key)
        dec = decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)
        assert dec == original

    def test_large_binary_roundtrip(self):
        """Larger binary (simulating real PE) survives roundtrip."""
        key = os.urandom(32)
        original = b"MZ\x90\x00" + os.urandom(10000)
        enc = encrypt_binary(original, key)
        dec = decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)
        assert dec == original

    def test_tamper_detection_hmac(self):
        """Modified ciphertext triggers HMAC failure."""
        key = os.urandom(32)
        enc = encrypt_binary(b"test payload", key)

        # Flip a byte in ciphertext
        raw = bytearray(b64d(enc["ciphertext"]))
        raw[0] ^= 0xFF
        enc["ciphertext"] = b64e(bytes(raw))

        with pytest.raises(ValueError, match="HMAC verification failed"):
            decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)

    def test_tamper_detection_gcm(self):
        """
        Modified ciphertext with recomputed HMAC still fails at GCM layer.
        This proves defence-in-depth: even if HMAC is bypassed, GCM catches it.
        """
        import hashlib, hmac

        key = os.urandom(32)
        enc = encrypt_binary(b"test payload", key)

        # Modify ciphertext
        raw = bytearray(b64d(enc["ciphertext"]))
        raw[0] ^= 0xFF
        modified_ct = bytes(raw)
        enc["ciphertext"] = b64e(modified_ct)

        # Recompute HMAC (bypassing HMAC check)
        nonce = b64d(enc["nonce"])
        new_mac = hmac.new(key, nonce + modified_ct, hashlib.sha256).digest()
        enc["hmac"] = b64e(new_mac)

        # GCM should still catch it (InvalidTag)
        with pytest.raises(Exception):
            decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)

    def test_wrong_key_fails(self):
        """Decryption with wrong key fails."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        enc = encrypt_binary(b"secret data", key1)

        with pytest.raises(Exception):
            decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key2)

    def test_nonce_uniqueness(self):
        """Each encryption produces a different nonce (replay protection)."""
        key = os.urandom(32)
        enc1 = encrypt_binary(b"data", key)
        enc2 = encrypt_binary(b"data", key)
        assert enc1["nonce"] != enc2["nonce"]


# =========================================================
# RSA Signature Tests
# =========================================================

class TestSignatures:
    @pytest.fixture
    def cert_paths(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        certs = root / "certs"
        return {
            "client_key": str(certs / "client.key"),
            "client_crt": certs / "client.crt",
            "server_key": str(certs / "server.key"),
        }

    def test_sign_verify_roundtrip(self, cert_paths):
        """Valid signature passes verification."""
        metadata = canonical_json({"client": "test", "timestamp": 123})
        sig = sign_metadata(metadata, cert_paths["client_key"])

        with open(cert_paths["client_crt"], "rb") as f:
            client_cert_pem = f.read()

        assert verify_signature(metadata, sig, client_cert_pem) is True

    def test_forged_signature_rejected(self, cert_paths):
        """Signature made with wrong key is rejected."""
        metadata = canonical_json({"client": "test", "timestamp": 123})

        # Sign with server key (wrong key)
        sig = sign_metadata(metadata, cert_paths["server_key"])

        # Verify against client cert (should fail)
        with open(cert_paths["client_crt"], "rb") as f:
            client_cert_pem = f.read()

        assert verify_signature(metadata, sig, client_cert_pem) is False

    def test_modified_metadata_rejected(self, cert_paths):
        """Signature fails if metadata is modified after signing."""
        original = canonical_json({"client": "test", "timestamp": 123})
        sig = sign_metadata(original, cert_paths["client_key"])

        # Modify metadata
        modified = canonical_json({"client": "attacker", "timestamp": 123})

        with open(cert_paths["client_crt"], "rb") as f:
            client_cert_pem = f.read()

        assert verify_signature(modified, sig, client_cert_pem) is False


# =========================================================
# Utility Tests
# =========================================================

class TestUtilities:
    def test_base64_roundtrip(self):
        """Base64 encode -> decode roundtrip."""
        data = os.urandom(64)
        assert b64d(b64e(data)) == data

    def test_sha256_hex(self):
        """SHA-256 produces correct hex digest."""
        assert sha256_hex(b"test") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_canonical_json_deterministic(self):
        """Canonical JSON is deterministic (sorted keys, no spaces)."""
        obj = {"b": 2, "a": 1}
        result = canonical_json(obj)
        assert result == b'{"a":1,"b":2}'
