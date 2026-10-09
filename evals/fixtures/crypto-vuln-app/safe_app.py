# SAFE counter-examples for crypto-vuln-app. An audit must NOT report these.
import hashlib
import secrets

import requests
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


def hash_password(password: str) -> str:
    # SAFE (vs SEC-01): salted, memory-hard KDF intended for passwords
    return hashlib.scrypt(password.encode(), salt=secrets.token_bytes(16),
                          n=2**15, r=8, p=1).hex()


def encrypt_field(data: bytes, key: bytes) -> bytes:
    # SAFE (vs SEC-02): authenticated encryption, random nonce per message
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ct


def make_reset_token() -> str:
    # SAFE (vs SEC-04): CSPRNG token, no user-derived structure
    return secrets.token_urlsafe(32)


def verify_webhook(url: str) -> dict:
    # SAFE (vs SEC-05): TLS verification on
    return requests.get(url, verify=True, timeout=5).json()


def derive_key(password: str, salt: bytes) -> bytes:
    # SAFE (vs SEC-06): 600k iterations, per-user salt
    return PBKDF2(password, salt, 32, count=600_000, hmac_hash_module=hashlib.sha256)


def _lenp(field: bytes) -> bytes:
    # SAFE (vs SEC-07): unambiguous length-prefixed encoding
    return len(field).to_bytes(8, "big") + field


def capability_digest(user: str, role: str, expires: str) -> str:
    # SAFE (vs SEC-07): domain/customization string + length prefixes —
    # no separator ambiguity, tuple-order-unique (TupleHash/SequenceHash
    # style); keyed flows use HMAC, never secret-prefix concatenation
    h = hashlib.sha256()
    h.update(b"capability-v1")
    for field in (user, role, expires):
        h.update(_lenp(field.encode()))
    return h.hexdigest()
