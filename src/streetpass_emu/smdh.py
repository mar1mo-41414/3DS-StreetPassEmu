"""SMDH: the standard Nintendo 3DS application banner/title-info format.

Public, well-documented, and not StreetPass-specific on its own -- reused
here because Mii Plaza's "recently played software" StreetPass list turned
out to embed this format's Title[16] array verbatim (immediately followed
by icon bitmap data), confirmed live against two real consoles' own local
icon caches: console A's real "FBI" homebrew banner, and several real retail
titles' banners (e.g. "New SUPER MARIO BROS. 2" / "Nintendo") on console B.

Only the Title[] array is implemented here -- the icon bitmap that follows
it in both a real SMDH file and Mii Plaza's embedded copy is not parsed
(its exact internal layout past "it starts right after the Title table"
isn't independently confirmed yet).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

SHORT_DESCRIPTION_SIZE = 0x80
LONG_DESCRIPTION_SIZE = 0x100
PUBLISHER_SIZE = 0x80
TITLE_ENTRY_SIZE = SHORT_DESCRIPTION_SIZE + LONG_DESCRIPTION_SIZE + PUBLISHER_SIZE  # 0x200

TITLE_COUNT = 16  # one per SMDH-supported UI language
TITLE_TABLE_SIZE = TITLE_ENTRY_SIZE * TITLE_COUNT  # 0x2000 = 8192, confirmed live


@dataclass(frozen=True)
class Title:
    """One language's worth of an SMDH's app banner text."""

    short_description: str
    long_description: str
    publisher: str


def _decode_fixed_utf16(data: bytes) -> str:
    return data.decode("utf-16-le").split("\0", 1)[0]


def _encode_fixed_utf16(text: str, size: int) -> bytes:
    encoded = text.encode("utf-16-le")
    if len(encoded) + 2 > size:
        raise ValueError(f"{text!r} is too long to fit in {size} bytes (including the NUL terminator)")
    return encoded.ljust(size, b"\0")


def parse_title(data: bytes) -> Title:
    if len(data) != TITLE_ENTRY_SIZE:
        raise ValueError(f"title entry must be {TITLE_ENTRY_SIZE} bytes, got {len(data)}")
    short_end = SHORT_DESCRIPTION_SIZE
    long_end = short_end + LONG_DESCRIPTION_SIZE
    return Title(
        short_description=_decode_fixed_utf16(data[0:short_end]),
        long_description=_decode_fixed_utf16(data[short_end:long_end]),
        publisher=_decode_fixed_utf16(data[long_end:]),
    )


def build_title(title: Title) -> bytes:
    return (
        _encode_fixed_utf16(title.short_description, SHORT_DESCRIPTION_SIZE)
        + _encode_fixed_utf16(title.long_description, LONG_DESCRIPTION_SIZE)
        + _encode_fixed_utf16(title.publisher, PUBLISHER_SIZE)
    )


def parse_title_table(data: bytes) -> List[Title]:
    """The 16-language Title[] array a real SMDH file carries at a fixed
    offset (0x8, right after its 8-byte header) -- Mii Plaza's "recently
    played" StreetPass list embeds this same array with no header at all."""
    if len(data) != TITLE_TABLE_SIZE:
        raise ValueError(f"title table must be {TITLE_TABLE_SIZE} bytes, got {len(data)}")
    return [parse_title(data[i:i + TITLE_ENTRY_SIZE]) for i in range(0, TITLE_TABLE_SIZE, TITLE_ENTRY_SIZE)]


def build_title_table(titles: List[Title]) -> bytes:
    """Builds a full 16-entry table. Fewer than 16 titles repeats the last
    one to fill the remainder -- every real capture so far had identical
    text in every language slot, so that's the sensible default; pass all
    16 explicitly if you need real per-language text."""
    if not titles:
        raise ValueError("titles must not be empty")
    if len(titles) > TITLE_COUNT:
        raise ValueError(f"at most {TITLE_COUNT} titles, got {len(titles)}")
    padded = titles + [titles[-1]] * (TITLE_COUNT - len(titles))
    return b"".join(build_title(t) for t in padded)


SMDH_MAGIC = b"SMDH"
SMDH_TITLES_OFFSET = 0x08
SMDH_SMALL_ICON_OFFSET = 0x2040   # 24x24 RGB565, 0x480 bytes
SMDH_LARGE_ICON_OFFSET = 0x24C0   # 48x48 RGB565, 0x1200 bytes
SMDH_SIZE = 0x36C0


@dataclass(frozen=True)
class Smdh:
    titles: List[Title]
    small_icon: bytes
    large_icon: bytes


def parse_smdh(data: bytes) -> Smdh:
    """Reads a standalone .smdh file (or the icon/banner block of a title). The Title[16] array and
    the two icon bitmaps are what a Mii Plaza StreetPass box carries (the 0x30-byte settings block
    in between is not part of the box)."""
    if len(data) < SMDH_SIZE or data[:4] != SMDH_MAGIC:
        raise ValueError("not an SMDH file")
    return Smdh(
        titles=parse_title_table(data[SMDH_TITLES_OFFSET:SMDH_TITLES_OFFSET + TITLE_TABLE_SIZE]),
        small_icon=bytes(data[SMDH_SMALL_ICON_OFFSET:SMDH_SMALL_ICON_OFFSET + 0x480]),
        large_icon=bytes(data[SMDH_LARGE_ICON_OFFSET:SMDH_LARGE_ICON_OFFSET + 0x1200]),
    )
