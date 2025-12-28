from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
import hashlib
import os

# -----------------------------
# KAW-SPN64 (Toy Block Cipher)
# Block: 128-bit (16 bytes)
# Key:   64-bit  (8 bytes)
# Rounds: 4 + final whitening
# -----------------------------

SBOX = [
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
]
INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# 128-bit bit permutation: position i -> PERM[i]
# We use a simple "multiply mod 127" style mapping for diffusion.
# Keep bit 127 fixed to make it bijective on 0..127.
PERM = [0] * 128
for i in range(127):
    PERM[i] = (i * 13) % 127
PERM[127] = 127

INV_PERM = [0] * 128
for i, p in enumerate(PERM):
    INV_PERM[p] = i

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _sub_bytes(block16: bytes) -> bytes:
    # apply nibble S-Box to each 4-bit chunk (32 nibbles)
    out = bytearray(16)
    for i, b in enumerate(block16):
        hi = SBOX[(b >> 4) & 0xF]
        lo = SBOX[b & 0xF]
        out[i] = (hi << 4) | lo
    return bytes(out)

def _inv_sub_bytes(block16: bytes) -> bytes:
    out = bytearray(16)
    for i, b in enumerate(block16):
        hi = INV_SBOX[(b >> 4) & 0xF]
        lo = INV_SBOX[b & 0xF]
        out[i] = (hi << 4) | lo
    return bytes(out)

def _bytes_to_bits128(block16: bytes) -> List[int]:
    bits = []
    for b in block16:
        for k in range(7, -1, -1):
            bits.append((b >> k) & 1)
    return bits  # length 128

def _bits128_to_bytes(bits: List[int]) -> bytes:
    out = bytearray(16)
    for i in range(16):
        val = 0
        for k in range(8):
            val = (val << 1) | bits[i*8 + k]
        out[i] = val
    return bytes(out)

def _permute_bits(block16: bytes) -> bytes:
    bits = _bytes_to_bits128(block16)
    out_bits = [0] * 128
    for i in range(128):
        out_bits[PERM[i]] = bits[i]
    return _bits128_to_bytes(out_bits)

def _inv_permute_bits(block16: bytes) -> bytes:
    bits = _bytes_to_bits128(block16)
    out_bits = [0] * 128
    for i in range(128):
        out_bits[INV_PERM[i]] = bits[i]
    return _bits128_to_bytes(out_bits)

def _rotl64(x: int, r: int) -> int:
    r %= 64
    return ((x << r) & ((1 << 64) - 1)) | (x >> (64 - r))

def _expand_key_64_to_round_keys(key8: bytes) -> List[bytes]:
    """
    Weak/simple key schedule on purpose:
    - Interpret key as 64-bit integer
    - For each round i: rotate and repeat to 16 bytes, then XOR a round constant
    This makes analysis/attack discussion easier.
    """
    if len(key8) != 8:
        raise ValueError("Key must be exactly 8 bytes (64-bit).")

    k = int.from_bytes(key8, "big")
    round_keys: List[bytes] = []
    for i in range(5):  # 4 rounds + final whitening
        ki = _rotl64(k, i * 11)  # rotation step
        rk = ki.to_bytes(8, "big") * 2  # 16 bytes by repetition
        # round constant: hash(i) low 16 bytes (keeps it deterministic)
        rc = hashlib.sha256(bytes([i])).digest()[:16]
        round_keys.append(_xor_bytes(rk, rc))
    return round_keys

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
    if not padded or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding.")
    if padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding.")
    return padded[:-pad_len]

def encrypt_block(block16: bytes, key8: bytes) -> bytes:
    if len(block16) != 16:
        raise ValueError("Block must be exactly 16 bytes.")
    rks = _expand_key_64_to_round_keys(key8)
    state = block16
    for i in range(4):
        state = _xor_bytes(state, rks[i])
        state = _sub_bytes(state)
        state = _permute_bits(state)
    state = _xor_bytes(state, rks[4])
    return state

def decrypt_block(block16: bytes, key8: bytes) -> bytes:
    if len(block16) != 16:
        raise ValueError("Block must be exactly 16 bytes.")
    rks = _expand_key_64_to_round_keys(key8)
    state = block16
    state = _xor_bytes(state, rks[4])
    for i in range(3, -1, -1):
        state = _inv_permute_bits(state)
        state = _inv_sub_bytes(state)
        state = _xor_bytes(state, rks[i])
    return state

def encrypt(plaintext: bytes, key8: bytes) -> bytes:
    data = pkcs7_pad(plaintext, 16)
    out = bytearray()
    for i in range(0, len(data), 16):
        out += encrypt_block(data[i:i+16], key8)
    return bytes(out)

def decrypt(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16.")
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        out += decrypt_block(ciphertext[i:i+16], key8)
    return pkcs7_unpad(bytes(out), 16)

def key_from_password(password: str) -> bytes:
    """
    Turn password into 64-bit key using SHA-256 (take first 8 bytes).
    (This is not the 'cipher security', just a convenience.)
    """
    return hashlib.sha256(password.encode("utf-8")).digest()[:8]

def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("Lengths must match.")
    dist = 0
    for x, y in zip(a, b):
        v = x ^ y
        dist += v.bit_count()
    return dist

if __name__ == "__main__":
    # Demo çıktı (hocaya göstermek için)
    key = key_from_password("deneme_parola")   # 8 byte key üretir
    text = b"Merhaba dunya"

    c = encrypt(text, key)
    p = decrypt(c, key)

    print("Duz Metin :", text)
    print("Anahtar   :", key.hex())
    print("Sifreli   :", c.hex())
    print("Cozulmus  :", p)

