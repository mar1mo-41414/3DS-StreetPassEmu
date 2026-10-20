"""Makes a new, random Mii (FFLStoreData) from nothing: a different "person" every call.

Layout per docs/EN/PROTOCOL_REFERENCE.md §9 (FFLStoreData, 96 bytes). Only the part *types* and colours
are random; sizes, positions and the header use the values a default Mii has, and every random index
stays inside the range the Mii Maker offers, so the console's Mii import accepts it. Identity (author_id,
mii_id) is fresh, which makes Mii Plaza treat the sender as a new visitor ("first meeting").
"""
from __future__ import annotations

import random
import struct
from typing import Optional

from .mii_qr import CHECKSUM_OFFSET, FFL_STORE_DATA_SIZE, crc16_xmodem, new_mii_id

NICKNAMES = ["ミィ", "ゆうき", "はるか", "そうた", "みお", "れん", "あおい", "ひなた", "りく", "ことは",
             "たける", "ななみ", "かいと", "さくら", "ゆうと", "めい"]


def _utf16(text: str, size: int) -> bytes:
    raw = text.encode("utf-16le")[:size]
    return raw + bytes(size - len(raw))


def random_mii(nickname: Optional[str] = None, creator: str = "", rng: Optional[random.Random] = None) -> bytes:
    """A valid, random 96-byte FFLStoreData. ``nickname`` is at most 10 characters (random if omitted)."""
    r = rng or random.SystemRandom()
    name = (nickname if nickname is not None else r.choice(NICKNAMES))[:10]
    m = bytearray(FFL_STORE_DATA_SIZE)
    m[0:4] = bytes([0x03, 0x00, 0x00, 0x30])                       # version 3, 3DS-generation Mii
    m[4:12] = bytes(r.getrandbits(8) for _ in range(8))             # author_id
    m[12:22] = new_mii_id(bytes(r.getrandbits(8) for _ in range(6)))
    m[0x16:0x1A] = bytes([0x00, 0x00, 0x00, 0x14])                  # no birthday, default favourite colour
    m[0x1A:0x2E] = _utf16(name, 20)
    m[0x2E] = m[0x2F] = 64                                           # height / weight: medium
    m[0x30] = (r.randrange(0, 6) << 5) | (r.randrange(0, 12) << 1)   # skin colour, face shape
    m[0x31] = 0                                                      # no makeup / wrinkles
    m[0x32] = r.randrange(0, 132)                                    # hair type
    m[0x33] = (r.randrange(0, 2) << 3) | r.randrange(0, 8)           # hair flip, hair colour
    struct.pack_into("<I", m, 0x34, r.randrange(0, 48) | (r.randrange(0, 6) << 6) | (4 << 9) | (3 << 13)
                     | (3 << 16) | (2 << 21) | (12 << 25))           # eyes: type, colour, size, stretch, ...
    struct.pack_into("<I", m, 0x38, r.randrange(0, 24) | (r.randrange(0, 8) << 5) | (4 << 8) | (3 << 12)
                     | (6 << 16) | (2 << 21) | (10 << 25))           # eyebrows
    struct.pack_into("<H", m, 0x3C, r.randrange(0, 12) | (4 << 5) | (9 << 9))                       # nose
    struct.pack_into("<H", m, 0x3E, r.randrange(0, 36) | (r.randrange(0, 5) << 6) | (4 << 9) | (3 << 13))  # mouth
    struct.pack_into("<H", m, 0x40, 13)                              # mouth height, no moustache
    struct.pack_into("<H", m, 0x42, (4 << 6) | (10 << 10))           # no beard
    struct.pack_into("<H", m, 0x44, (4 << 7) | (10 << 11))           # no glasses
    struct.pack_into("<H", m, 0x46, (4 << 1) | (2 << 5) | (20 << 10))  # mole present in the data but disabled
    m[0x48:0x5C] = _utf16(creator[:10], 20)
    m[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2] = crc16_xmodem(bytes(m[:CHECKSUM_OFFSET])).to_bytes(2, "big")
    return bytes(m)
