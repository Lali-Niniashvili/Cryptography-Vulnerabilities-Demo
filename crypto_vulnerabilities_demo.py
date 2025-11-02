#!/usr/bin/env python3
"""
Crypto Vulnerabilities Demo for Beginners
Shows: Timing Attacks, Padding Oracle, Nonce Reuse, Weak Comparison
"""

import time
import os
import hashlib
import statistics
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from nacl.secret import SecretBox
from nacl.utils import random
from nacl import bindings

print("Cryptography Vulnerabilities Demo for Beginners")
print("=" * 60)

# ===================================================================
# 1. TIMING ATTACK: String Comparison
# ===================================================================
print("\n1. Timing Attack on Password Comparison")

SECRET_PASSWORD = b"correcthorsebatterystaple"

def vulnerable_equals(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True

def secure_equals(a: bytes, b: bytes) -> bool:
    a = a.ljust(32, b'\x00')
    b = b.ljust(32, b'\x00')
    return bindings.crypto_verify_32(a, b) == 0

def measure(func, inp):
    start = time.perf_counter_ns()
    func(inp, SECRET_PASSWORD)
    return time.perf_counter_ns() - start

prefixes = [b"", b"c", b"co", b"corr", b"correcthorsebatterystapl"]
print("   Guessing password byte-by-byte...")
for p in prefixes:
    t = statistics.mean([measure(vulnerable_equals, p) for _ in range(1000)])
    print(f"     Guess '{p.decode(errors='ignore'):<25}' → {t/1000:.1f} µs")

secure_time = statistics.mean([measure(secure_equals, b"a"*25) for _ in range(1000)])
print(f"   Secure compare: always ~{secure_time/1000:.1f} µs → NO LEAK!")

# ===================================================================
# 2. PADDING ORACLE: AES-CBC
# ===================================================================
print("\n2. Padding Oracle Attack (AES-CBC)")

key, iv = os.urandom(32), os.urandom(16)

def encrypt_cbc(msg: str) -> bytes:
    c = AES.new(key, AES.MODE_CBC, iv)
    return iv + c.encrypt(pad(msg.encode(), 16))

def decrypt_cbc_vuln(ct: bytes) -> str:
    iv, data = ct[:16], ct[16:]
    c = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(c.decrypt(data), 16).decode()
    except:
        raise ValueError("Invalid padding!")

msg = "Secret message!"
ct = encrypt_cbc(msg)
print(f"   Normal decrypt: {decrypt_cbc_vuln(ct)}")

attack_ct = bytearray(ct)
attack_ct[-1] ^= 1
try:
    decrypt_cbc_vuln(attack_ct)
except ValueError as e:
    print(f"   Attacker sees: '{e}' → Can recover plaintext!")

# ===================================================================
# 3. NONCE REUSE: AES-GCM
# ===================================================================
print("\n3. Nonce Reuse Attack (AES-GCM)")

box = SecretBox(os.urandom(32))
nonce = os.urandom(24)

m1, m2 = b"Pay Alice $100", b"Pay Bob   $100"
c1, c2 = box.encrypt(m1, nonce), box.encrypt(m2, nonce)

xor = bytes(a ^ b for a, b in zip(c1, c2))
print(f"   XOR of ciphertexts reveals: {xor}")

# ===================================================================
# 4. SECURE IMPLEMENTATION
# ===================================================================
print("\n4. Secure Encryption (AEAD + Key Derivation)")

def secure_encrypt(data: str, pwd: str) -> bytes:
    salt = os.urandom(16)
    key = hashlib.scrypt(pwd.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    box = SecretBox(key)
    nonce = random(24)
    ct = box.encrypt(data.encode(), nonce)
    return salt + nonce + ct

def secure_decrypt(blob: bytes, pwd: str) -> str:
    salt, nonce, ct = blob[:16], blob[16:40], blob[40:]
    key = hashlib.scrypt(pwd.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return SecretBox(key).decrypt(ct, nonce).decode()

enc = secure_encrypt("My PIN is 1234", "pass123")
print(f"   Decrypted: {secure_decrypt(enc, 'pass123')}")

# Tamper
bad = bytearray(enc); bad[-1] ^= 0xFF
try:
    secure_decrypt(bad, "pass123")
except:
    print("   Tampered → Auth failed! (Secure)")

# ===================================================================
# SUMMARY
# ===================================================================
print("\n" + "="*60)
print("SUMMARY: Fix These Bugs!")
print("- Use AEAD (AES-GCM, ChaCha20-Poly1305)")
print("- Never reuse nonces")
print("- Use constant-time comparisons")
print("- Hash passwords with Argon2/scrypt")
print("- Prefer PyNaCl over raw Crypto")
print("="*60)
