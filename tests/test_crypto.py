import base64
import re

import pytest

from blurr import BlurrError, decrypt, encrypt

KEY = "测试 key with spaces 123"


def test_v1_compatibility_vector():
    # Fixed salt/nonce, generated independently through Scrypt + AESGCM directly.
    # Retain this fixture when adding new format versions.
    armored = (
        "Blurr1 AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWDJTV5VJ52VP"
        "B3CGG22VTISJZMBQXGTUVO4KMT6G4UB4LVJB6EYLII"
    )
    assert decrypt(armored, "兼容性 key") == "Blurr v1 中文\r\n".encode("utf-8")


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "gbk", "gb18030", "big5", "utf-16", "utf-16-be", "utf-32"])
def test_encoding_roundtrip(encoding):
    original = "中文內容 English 123\r\n第二行\n".encode(encoding)
    armored = encrypt(original, KEY)
    assert re.fullmatch(r"[A-Za-z0-9 ]+", armored)
    assert decrypt(armored, KEY) == original


@pytest.mark.parametrize("original", [b"", b"\x00\x00\xff", bytes(range(256)) * 4096, "😀你好é\n".encode()])
def test_bytes_roundtrip(original):
    armored = encrypt(original, KEY)
    assert set(armored) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ")
    assert decrypt(armored, KEY) == original


def test_random_salt_and_nonce():
    first, second = encrypt(b"same input", KEY), encrypt(b"same input", KEY)
    assert first != second
    assert decrypt(first, KEY) == decrypt(second, KEY) == b"same input"


@pytest.mark.parametrize("wrong_key", ["wrong", KEY + " ", KEY.upper()])
def test_wrong_key(wrong_key):
    with pytest.raises(BlurrError, match="incorrect key or damaged"):
        decrypt(encrypt(b"private", KEY), wrong_key)


@pytest.mark.parametrize("index", [0, 16, 28, -1])
def test_tamper_salt_nonce_ciphertext_and_tag(index):
    armored = encrypt(b"private", KEY)
    body = armored.partition(" ")[2].replace(" ", "")
    payload = bytearray(base64.b32decode(body + "=" * (-len(body) % 8)))
    payload[index] ^= 1
    modified = "Blurr1 " + base64.b32encode(payload).decode().rstrip("=")
    with pytest.raises(BlurrError, match="incorrect key or damaged"):
        decrypt(modified, KEY)


@pytest.mark.parametrize("malformed", ["", "Blurr2 AAAA", "Blurr1 ", "Blurr1 A", "Blurr1 AA", "Blurr1 AB", "Blurr1 00000", "Blurr1 ABC=", "Blurr1 abcd", "Blurr1 中文", "Blurr1 AAA\n", "Blurr1 AAA\t"])
def test_malformed_input(malformed):
    with pytest.raises(BlurrError):
        decrypt(malformed, KEY)


def test_regrouping_spaces():
    armored = encrypt(b"hello", KEY)
    prefix, _, body = armored.partition(" ")
    assert decrypt("  " + prefix + "   " + " ".join(body.replace(" ", "")) + " ", KEY) == b"hello"


def test_appending_and_truncating_valid_characters():
    armored = encrypt(b"hello", KEY)
    for modified in (armored[:-4], armored + "AAAA"):
        with pytest.raises(BlurrError):
            decrypt(modified, KEY)


def test_empty_key():
    with pytest.raises(BlurrError, match="empty"):
        encrypt(b"hello", "")
    with pytest.raises(BlurrError, match="empty"):
        decrypt("Blurr1 AAAA", "")
