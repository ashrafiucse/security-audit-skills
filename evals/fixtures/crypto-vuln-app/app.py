# Fixture: intentionally weak crypto. FAKE data only.
# Covers crypto-review's usage-context table end to end.
# Expected findings: see expected-findings.md
import hashlib
import math
import random

import requests
from Crypto.Cipher import DES, AES
from Crypto.Protocol.KDF import PBKDF2


def hash_password(password: str) -> str:
    # SEC-01: fast unsalted hash for password storage
    return hashlib.md5(password.encode()).hexdigest()


def encrypt_card(number: str) -> bytes:
    # SEC-02: ECB mode — identical plaintext blocks leak (and no auth)
    cipher = AES.new(b"0123456789abcdef0123456789abcdef", AES.MODE_ECB)
    return cipher.encrypt(number.encode().ljust(32, b"\0"))


def legacy_encrypt(data: bytes) -> bytes:
    # SEC-03: DES — 56-bit key, broken decades ago
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return cipher.encrypt(data.ljust(8, b"\0"))


def make_reset_token(user_id: int) -> str:
    # SEC-04: password-reset token from a non-CSPRNG
    return f"{user_id}-{random.randint(0, 999999)}"


def verify_webhook(url: str) -> dict:
    # SEC-05: TLS verification disabled
    return requests.get(url, verify=False, timeout=5).json()


def derive_key(password: str) -> bytes:
    # SEC-06: PBKDF2 with trivial iteration count
    return PBKDF2(password, b"staticsalt", 16, count=1000)
