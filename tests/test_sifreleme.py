import sys
import os

# src klasörünü tanıt
sys.path.append(os.path.abspath("src"))

from sifreleme_algoritmasi import (
    encrypt,
    decrypt,
    encrypt_block,
    decrypt_block,
    key_from_password,
    hamming_distance_bytes
)


def test_basic_roundtrip():
    key = key_from_password("test123")
    text = b"merhaba"
    c = encrypt(text, key)
    p = decrypt(c, key)
    assert p == text


def test_block_encrypt_decrypt():
    key = key_from_password("abc")
    block = b"1234567890abcdef"
    c = encrypt_block(block, key)
    p = decrypt_block(c, key)
    assert p == block


def test_key_avalanche():
    key1 = key_from_password("abc")
    key2 = bytearray(key1)
    key2[0] ^= 1

    text = b"merhaba dunya"
    c1 = encrypt(text, key1)
    c2 = encrypt(text, bytes(key2))

    diff = hamming_distance_bytes(c1, c2)
    assert diff > 10

