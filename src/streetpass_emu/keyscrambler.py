"""The 3DS AES "key scrambler": combines a keyslot's KeyX and KeyY into the
normal key the AES engine actually encrypts/decrypts with.

This formula itself is not secret -- it's documented on 3dbrew ("AES
Registers"/general 3DS crypto community knowledge) and implemented in every
3DS crypto tool, including this project's own pyctr dependency
(`pyctr.crypto.engine.CryptoEngine.keygen_manual`), which this reproduces.
What *is* sensitive is any particular keyslot's actual KeyX/KeyY bytes (see
keyslot_2e.py for how those are supplied for keyslot 0x2E specifically).
"""

from __future__ import annotations

KEYSCRAMBLER_CONSTANT = 0x1FF9E9AAC5FE0408024591DC5D52768A


def _rol(val: int, r_bits: int, max_bits: int) -> int:
    r_bits %= max_bits
    mask = (1 << max_bits) - 1
    return ((val << r_bits) & mask) | ((val & mask) >> (max_bits - r_bits))


def keygen_manual(key_x: bytes, key_y: bytes) -> bytes:
    """3DS (not DSi) AES key scrambler: normal_key = rol(rol(keyX, 2) XOR
    keyY + constant, 87), all as 128-bit values."""
    if len(key_x) != 16 or len(key_y) != 16:
        raise ValueError(f"key_x and key_y must both be 16 bytes, got {len(key_x)} and {len(key_y)}")
    x = int.from_bytes(key_x, "big")
    y = int.from_bytes(key_y, "big")
    combined = (_rol(x, 2, 128) ^ y) + KEYSCRAMBLER_CONSTANT
    return _rol(combined, 87, 128).to_bytes(16, "big")
