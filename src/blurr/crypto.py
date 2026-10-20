"""Versioned byte encryption; text armoring uses standard unpadded Base32."""

import base64
import binascii
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_PREFIX = "Blurr1"
_SALT_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16
_HEADER_SIZE = _SALT_SIZE + _NONCE_SIZE
# This domain separator fixes the algorithm and KDF parameters for v1.
_AAD = b"Blurr1 AES256GCM Scrypt N131072 r8 p1"


class BlurrError(ValueError):
    """Invalid key, unsupported format, or failed authentication."""


def _derive_key(key: str, salt: bytes) -> bytes:
    if not key:
        raise BlurrError("Key must not be empty.")
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(
        key.encode("utf-8")
    )


def encrypt(data: bytes, key: str) -> str:
    """Encrypt bytes to ASCII letters, digits and ordinary spaces only."""
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext = AESGCM(_derive_key(key, salt)).encrypt(nonce, data, _AAD)
    body = base64.b32encode(salt + nonce + ciphertext).decode("ascii").rstrip("=")
    return _PREFIX + " " + " ".join(
        body[index : index + 16] for index in range(0, len(body), 16)
    )


def decrypt(text: str, key: str) -> bytes:
    """Authenticate before returning the original bytes; spaces may be regrouped."""
    if not key:
        raise BlurrError("Key must not be empty.")
    if not re.fullmatch(r"[A-Za-z0-9 ]+", text):
        raise BlurrError("Ciphertext must contain only ASCII letters, digits and spaces.")
    prefix, separator, body = text.strip(" ").partition(" ")
    if prefix != _PREFIX or not separator:
        raise BlurrError("Unsupported or missing Blurr format version.")
    body = body.replace(" ", "")
    try:
        payload = base64.b32decode(body + "=" * (-len(body) % 8))
    except (binascii.Error, ValueError) as exc:
        raise BlurrError("Invalid ciphertext encoding.") from exc
    # Reject aliases differing only in unused trailing bits.
    if base64.b32encode(payload).decode("ascii").rstrip("=") != body:
        raise BlurrError("Invalid ciphertext encoding.")
    if len(payload) < _HEADER_SIZE + _TAG_SIZE:
        raise BlurrError("Ciphertext is truncated.")
    salt = payload[:_SALT_SIZE]
    nonce = payload[_SALT_SIZE:_HEADER_SIZE]
    try:
        return AESGCM(_derive_key(key, salt)).decrypt(nonce, payload[_HEADER_SIZE:], _AAD)
    except InvalidTag as exc:
        raise BlurrError("Decryption failed: incorrect key or damaged ciphertext.") from exc
