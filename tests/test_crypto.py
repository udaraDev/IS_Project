import os
import pytest
from common.crypto_utils import *


def test_hybrid_key_agreement():
    c_priv, c_pub = generate_ecdh_keypair()
    s_priv, s_pub = generate_ecdh_keypair()
    c_ecdh = ecdh_derive(c_priv, s_pub)
    s_ecdh = ecdh_derive(s_priv, c_pub)
    assert c_ecdh == s_ecdh


def test_kyber_roundtrip():
    kp = kyber_keygen()
    ct, ss1 = kyber_encapsulate(kp.public_key)
    ss2 = kyber_decapsulate(ct, kp.secret_key)
    assert ss1 == ss2


def test_encrypt_decrypt_roundtrip():
    key = os.urandom(32)
    original = b"MZ\x90\x00" + os.urandom(256)
    enc = encrypt_binary(original, key)
    dec = decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)
    assert dec == original


def test_tamper_detection():
    key = os.urandom(32)
    enc = encrypt_binary(b"hello", key)
    raw = bytearray(b64d(enc["ciphertext"]))
    raw[0] ^= 1
    enc["ciphertext"] = b64e(bytes(raw))
    with pytest.raises(ValueError):
        decrypt_binary(enc["nonce"], enc["ciphertext"], enc["hmac"], key)
