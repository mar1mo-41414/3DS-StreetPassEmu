"""RGB565 icon bitmaps as stored in SMDH files and in StreetPass TMP Boxes.

The 3DS GPU (PICA200) stores textures as 8x8 pixel tiles, left to right and top to bottom,
and the pixels inside a tile follow a Z-order (Morton) curve. SMDH icons are plain RGB565
(little-endian u16) in that layout: 24x24 (1152 B) and 48x48 (4608 B) in the SMDH itself,
and 40x40 (3200 B) in the TLV of a Mii Plaza message header.

Pure Python; a pixel is an ``(r, g, b)`` tuple of 0-255 ints, an image is a row-major list of
pixels. ``from_png``/``to_png`` use Pillow if it is installed.
"""
from __future__ import annotations

import struct
from pathlib import Path

Pixel = tuple[int, int, int]

SMALL_SIZE = 24   # 1152 bytes
LARGE_SIZE = 48   # 4608 bytes
TLV_SIZE = 40     # 3200 bytes (Mii Plaza message header icon)


def icon_bytes(size: int) -> int:
    return size * size * 2


def _morton(x: int, y: int) -> int:
    """Position inside an 8x8 tile: x/y bits interleaved, x in the even bits."""
    return ((x & 1) | ((y & 1) << 1) | ((x & 2) << 1) | ((y & 2) << 2)
            | ((x & 4) << 2) | ((y & 4) << 3))


def _check(size: int) -> None:
    if size <= 0 or size % 8:
        raise ValueError(f"icon size must be a positive multiple of 8, got {size}")


def pack565(p: Pixel) -> int:
    r, g, b = p
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def unpack565(v: int) -> Pixel:
    r, g, b = (v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F
    return (r << 3 | r >> 2, g << 2 | g >> 4, b << 3 | b >> 2)


def encode(pixels: list[Pixel], size: int) -> bytes:
    """Row-major ``size*size`` pixels -> tiled, Z-ordered RGB565 bytes."""
    _check(size)
    if len(pixels) != size * size:
        raise ValueError(f"expected {size * size} pixels, got {len(pixels)}")
    out = bytearray(icon_bytes(size))
    tiles_per_row = size // 8
    for y in range(size):
        for x in range(size):
            tile = (y // 8) * tiles_per_row + x // 8
            idx = tile * 64 + _morton(x % 8, y % 8)
            struct.pack_into("<H", out, idx * 2, pack565(pixels[y * size + x]))
    return bytes(out)


def decode(data: bytes, size: int) -> list[Pixel]:
    """Tiled, Z-ordered RGB565 bytes -> row-major pixels."""
    _check(size)
    if len(data) != icon_bytes(size):
        raise ValueError(f"expected {icon_bytes(size)} bytes, got {len(data)}")
    tiles_per_row = size // 8
    pixels: list[Pixel] = []
    for y in range(size):
        for x in range(size):
            tile = (y // 8) * tiles_per_row + x // 8
            idx = tile * 64 + _morton(x % 8, y % 8)
            pixels.append(unpack565(struct.unpack_from("<H", data, idx * 2)[0]))
    return pixels


def solid(size: int, color: Pixel) -> bytes:
    return encode([color] * (size * size), size)


def from_png(path: Path, size: int) -> bytes:
    """Loads any image Pillow can read, scales it to ``size``x``size`` and encodes it."""
    from PIL import Image  # optional dependency (pip install pillow)
    img = Image.open(path).convert("RGBA")
    bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
    img = Image.alpha_composite(bg, img).convert("RGB").resize((size, size), Image.LANCZOS)
    return encode(list(img.getdata()), size)


def to_png(data: bytes, size: int, path: Path, scale: int = 1) -> None:
    from PIL import Image
    img = Image.new("RGB", (size, size))
    img.putdata(decode(data, size))
    if scale != 1:
        img = img.resize((size * scale, size * scale), Image.NEAREST)
    img.save(path)
