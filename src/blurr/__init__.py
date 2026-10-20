"""Blurr: authenticated encryption with alphanumeric text output."""

from blurr.crypto import BlurrError, decrypt, encrypt

__all__ = ["BlurrError", "decrypt", "encrypt"]
__version__ = "0.1.0"
