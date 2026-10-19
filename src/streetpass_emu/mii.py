"""FFLiMiiDataCore / FFLiMiiDataOfficial / FFLStoreData: the compact,
bit-packed "gen2" Mii binary format shared across Wii U (nn::ffl,
"FFLStoreData") and, under a different name ("CFLStoreData"/CFL_DB), the
3DS. Public, well-documented (mirrored e.g. in devkitPro/wut's
include/nn/ffl/miidata.h, itself citing decaf-emu's Wii U emulator source)
-- not StreetPass-specific, reused here because Mii Plaza's CFL_DB (a
real 3DS's own Mii database) stores Miis in
exactly this shape.

Confirmed live against a real 3DS's own Mii database: decoding birth_month/birth_day/gender from a real Mii record
produced exactly the console owner's actual Mii birthday and gender,
byte-for-byte. One correction versus a naive reading of the public C
header: its bitfields are declared as if the *first*-declared field
occupies the *low* bits of the underlying little-endian storage unit --
reading them that way gave an invalid month (13). Reading the other way
(first-declared field in the *high* bits) gives the correct, real value,
so that's what this module implements throughout. Only that one field
(birth_day/birth_month/gender/favorite_color, all packed into the same
u16) was independently checked against real data; every other bitfield
group here follows the same convention by consistency, not by its own
independent real-data check.

Field names follow the C header as closely as possible (including its
"unk_" placeholders for fields whose meaning isn't documented there).
mii_name/creator_name are UTF-16, matching every other StreetPass text
field in this codebase.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

CREATE_ID_SIZE = 10
CORE_SIZE = 0x48
OFFICIAL_SIZE = 0x5C  # CORE_SIZE + creator_name -- matches CFL_DB's own entry size
STORE_DATA_SIZE = 0x60  # OFFICIAL_SIZE + unk + checksum -- the size a QR code / FFLStoreData file carries

NAME_SIZE = 20  # 10 UTF-16 characters, no guaranteed NUL terminator


def _split_bits_msb_first(value: int, widths: List[int]) -> List[int]:
    """Splits `value` into fields per `widths`, in MSB-first declaration
    order (project findings's bit-order finding)."""
    total_bits = sum(widths)
    fields = []
    remaining = total_bits
    for w in widths:
        remaining -= w
        fields.append((value >> remaining) & ((1 << w) - 1))
    return fields


def _join_bits_msb_first(fields: List[int], widths: List[int]) -> int:
    value = 0
    for field, w in zip(fields, widths):
        if not (0 <= field < (1 << w)):
            raise ValueError(f"value {field} doesn't fit in {w} bits")
        value = (value << w) | field
    return value


def _decode_utf16_field(data: bytes) -> str:
    return data.decode("utf-16-le").split("\0", 1)[0]


def _encode_utf16_field(text: str, size: int) -> bytes:
    encoded = text.encode("utf-16-le")
    if len(encoded) > size:
        raise ValueError(f"{text!r} is too long to fit in {size} bytes")
    return encoded.ljust(size, b"\0")


@dataclass(frozen=True)
class CreateID:
    """FFLCreateID: identifies when/where/on-what a Mii was created."""

    flags: int  # 4 bits
    timestamp: int  # 28 bits
    device_hash: bytes  # 6 bytes


def parse_create_id(data: bytes) -> CreateID:
    if len(data) != CREATE_ID_SIZE:
        raise ValueError(f"CreateID must be {CREATE_ID_SIZE} bytes, got {len(data)}")
    packed = int.from_bytes(data[0:4], "little")
    flags, timestamp = _split_bits_msb_first(packed, [4, 28])
    return CreateID(flags=flags, timestamp=timestamp, device_hash=data[4:10])


def build_create_id(create_id: CreateID) -> bytes:
    packed = _join_bits_msb_first([create_id.flags, create_id.timestamp], [4, 28])
    if len(create_id.device_hash) != 6:
        raise ValueError(f"device_hash must be 6 bytes, got {len(create_id.device_hash)}")
    return packed.to_bytes(4, "little") + create_id.device_hash


@dataclass(frozen=True)
class MiiCore:
    """FFLiMiiDataCore (0x48 bytes): a Mii's appearance, name, and birth
    info -- everything but the creator's own name (see MiiOfficial)."""

    birth_platform: int
    font_region: int
    region_move: int
    copyable: bool
    mii_version: int
    author_id: int
    mii_id: CreateID
    favorite_color: int
    birth_month: int
    birth_day: int
    gender: int  # 0 = male, 1 = female
    mii_name: str
    height: int
    build: int  # "fatness" in the C header
    blush_type: int
    face_style: int
    face_color: int
    face_type: int
    local_only: bool
    hair_mirrored: int  # 5 bits -- despite the C header's name, this isn't a 1-bit flip flag
    hair_color: int
    hair_type: int
    eye_thickness: int
    eye_scale: int
    eye_color: int
    eye_type: int
    eye_height: int
    eye_distance: int
    eye_rotation: int
    eyebrow_thickness: int
    eyebrow_scale: int
    eyebrow_color: int
    eyebrow_type: int
    eyebrow_height: int
    eyebrow_distance: int
    eyebrow_rotation: int
    nose_height: int
    nose_scale: int
    nose_type: int
    mouth_thickness: int
    mouth_scale: int
    mouth_color: int
    mouth_type: int
    mustache_type: int
    mouth_height: int
    mustache_height: int
    mustache_scale: int
    beard_color: int
    beard_type: int
    glass_height: int
    glass_scale: int
    glass_color: int
    glass_type: int
    mole_ypos: int
    mole_xpos: int
    mole_scale: int
    mole_enabled: bool


def parse_mii_core(data: bytes) -> MiiCore:
    if len(data) != CORE_SIZE:
        raise ValueError(f"MiiCore must be {CORE_SIZE} bytes, got {len(data)}")

    b00 = data[0x00]
    birth_platform, _unk_0x00_b4 = _split_bits_msb_first(b00, [4, 4])

    b02 = data[0x02]
    font_region, region_move, _unk_0x02_b6, copyable = _split_bits_msb_first(b02, [4, 2, 1, 1])

    mii_version = data[0x03]
    author_id = int.from_bytes(data[0x04:0x0C], "little")
    mii_id = parse_create_id(data[0x0C:0x16])

    b18 = int.from_bytes(data[0x18:0x1A], "little")
    _u0, _u1, favorite_color, birth_day, birth_month, gender = _split_bits_msb_first(b18, [1, 1, 4, 5, 4, 1])

    mii_name = _decode_utf16_field(data[0x1A:0x1A + NAME_SIZE])
    height = data[0x2E]
    build = data[0x2F]

    blush_type, face_style = _split_bits_msb_first(data[0x30], [4, 4])
    face_color, face_type, local_only = _split_bits_msb_first(data[0x31], [3, 4, 1])
    hair_mirrored, hair_color = _split_bits_msb_first(data[0x32], [5, 3])
    hair_type = data[0x33]

    eye = int.from_bytes(data[0x34:0x38], "little")
    eye_thickness, eye_scale, eye_color, eye_type, eye_height, eye_distance, eye_rotation = \
        _split_bits_msb_first(eye, [3, 4, 3, 6, 7, 4, 5])

    eyebrow = int.from_bytes(data[0x38:0x3C], "little")
    eyebrow_thickness, eyebrow_scale, eyebrow_color, eyebrow_type, eyebrow_height, eyebrow_distance, eyebrow_rotation = \
        _split_bits_msb_first(eyebrow, [4, 4, 3, 5, 7, 4, 5])

    nose_mouth = int.from_bytes(data[0x3C:0x40], "little")
    nose_height, nose_scale, nose_type, mouth_thickness, mouth_scale, mouth_color, mouth_type = \
        _split_bits_msb_first(nose_mouth, [7, 4, 5, 3, 4, 3, 6])

    beard = int.from_bytes(data[0x40:0x44], "little")
    _unk_0x40, mustache_type, mouth_height, mustache_height, mustache_scale, beard_color, beard_type = \
        _split_bits_msb_first(beard, [8, 3, 5, 6, 4, 3, 3])

    glass = int.from_bytes(data[0x44:0x46], "little")
    glass_height, glass_scale, glass_color, glass_type = _split_bits_msb_first(glass, [5, 4, 3, 4])

    mole = int.from_bytes(data[0x46:0x48], "little")
    _unk_0x46_b0, mole_ypos, mole_xpos, mole_scale, mole_enabled = _split_bits_msb_first(mole, [1, 5, 5, 4, 1])

    return MiiCore(
        birth_platform=birth_platform, font_region=font_region, region_move=region_move, copyable=bool(copyable),
        mii_version=mii_version, author_id=author_id, mii_id=mii_id,
        favorite_color=favorite_color, birth_month=birth_month, birth_day=birth_day, gender=gender,
        mii_name=mii_name, height=height, build=build,
        blush_type=blush_type, face_style=face_style, face_color=face_color, face_type=face_type,
        local_only=bool(local_only), hair_mirrored=hair_mirrored, hair_color=hair_color, hair_type=hair_type,
        eye_thickness=eye_thickness, eye_scale=eye_scale, eye_color=eye_color, eye_type=eye_type,
        eye_height=eye_height, eye_distance=eye_distance, eye_rotation=eye_rotation,
        eyebrow_thickness=eyebrow_thickness, eyebrow_scale=eyebrow_scale, eyebrow_color=eyebrow_color,
        eyebrow_type=eyebrow_type, eyebrow_height=eyebrow_height, eyebrow_distance=eyebrow_distance,
        eyebrow_rotation=eyebrow_rotation,
        nose_height=nose_height, nose_scale=nose_scale, nose_type=nose_type,
        mouth_thickness=mouth_thickness, mouth_scale=mouth_scale, mouth_color=mouth_color, mouth_type=mouth_type,
        mustache_type=mustache_type, mouth_height=mouth_height, mustache_height=mustache_height,
        mustache_scale=mustache_scale, beard_color=beard_color, beard_type=beard_type,
        glass_height=glass_height, glass_scale=glass_scale, glass_color=glass_color, glass_type=glass_type,
        mole_ypos=mole_ypos, mole_xpos=mole_xpos, mole_scale=mole_scale, mole_enabled=bool(mole_enabled),
    )


def build_mii_core(mii: MiiCore) -> bytes:
    """Note: this zeroes every bit this module doesn't have a named field
    for (the C header's own "unk_..." placeholders), rather than
    round-tripping them -- parsing real data and rebuilding it will not
    reproduce those specific bits, only every named field."""
    out = bytearray(CORE_SIZE)
    out[0x00] = _join_bits_msb_first([mii.birth_platform, 0], [4, 4])
    out[0x01] = 0
    out[0x02] = _join_bits_msb_first([mii.font_region, mii.region_move, 0, int(mii.copyable)], [4, 2, 1, 1])
    out[0x03] = mii.mii_version
    out[0x04:0x0C] = mii.author_id.to_bytes(8, "little")
    out[0x0C:0x16] = build_create_id(mii.mii_id)
    out[0x16:0x18] = bytes(2)

    b18 = _join_bits_msb_first([0, 0, mii.favorite_color, mii.birth_day, mii.birth_month, mii.gender], [1, 1, 4, 5, 4, 1])
    out[0x18:0x1A] = b18.to_bytes(2, "little")

    out[0x1A:0x1A + NAME_SIZE] = _encode_utf16_field(mii.mii_name, NAME_SIZE)
    out[0x2E] = mii.height
    out[0x2F] = mii.build

    out[0x30] = _join_bits_msb_first([mii.blush_type, mii.face_style], [4, 4])
    out[0x31] = _join_bits_msb_first([mii.face_color, mii.face_type, int(mii.local_only)], [3, 4, 1])
    out[0x32] = _join_bits_msb_first([mii.hair_mirrored, mii.hair_color], [5, 3])
    out[0x33] = mii.hair_type

    eye = _join_bits_msb_first(
        [mii.eye_thickness, mii.eye_scale, mii.eye_color, mii.eye_type, mii.eye_height, mii.eye_distance, mii.eye_rotation],
        [3, 4, 3, 6, 7, 4, 5],
    )
    out[0x34:0x38] = eye.to_bytes(4, "little")

    eyebrow = _join_bits_msb_first(
        [mii.eyebrow_thickness, mii.eyebrow_scale, mii.eyebrow_color, mii.eyebrow_type, mii.eyebrow_height,
         mii.eyebrow_distance, mii.eyebrow_rotation],
        [4, 4, 3, 5, 7, 4, 5],
    )
    out[0x38:0x3C] = eyebrow.to_bytes(4, "little")

    nose_mouth = _join_bits_msb_first(
        [mii.nose_height, mii.nose_scale, mii.nose_type, mii.mouth_thickness, mii.mouth_scale, mii.mouth_color,
         mii.mouth_type],
        [7, 4, 5, 3, 4, 3, 6],
    )
    out[0x3C:0x40] = nose_mouth.to_bytes(4, "little")

    beard = _join_bits_msb_first(
        [0, mii.mustache_type, mii.mouth_height, mii.mustache_height, mii.mustache_scale, mii.beard_color,
         mii.beard_type],
        [8, 3, 5, 6, 4, 3, 3],
    )
    out[0x40:0x44] = beard.to_bytes(4, "little")

    glass = _join_bits_msb_first([mii.glass_height, mii.glass_scale, mii.glass_color, mii.glass_type], [5, 4, 3, 4])
    out[0x44:0x46] = glass.to_bytes(2, "little")

    mole = _join_bits_msb_first([0, mii.mole_ypos, mii.mole_xpos, mii.mole_scale, int(mii.mole_enabled)], [1, 5, 5, 4, 1])
    out[0x46:0x48] = mole.to_bytes(2, "little")

    return bytes(out)


@dataclass(frozen=True)
class MiiOfficial:
    """FFLiMiiDataOfficial (0x5C bytes): a MiiCore plus the name of
    whoever created it. This is the exact shape CFL_DB (a real 3DS's own
    Mii database) stores each Mii as."""

    core: MiiCore
    creator_name: str


def parse_mii_official(data: bytes) -> MiiOfficial:
    if len(data) != OFFICIAL_SIZE:
        raise ValueError(f"MiiOfficial must be {OFFICIAL_SIZE} bytes, got {len(data)}")
    core = parse_mii_core(data[0:CORE_SIZE])
    creator_name = _decode_utf16_field(data[CORE_SIZE:CORE_SIZE + NAME_SIZE])
    return MiiOfficial(core=core, creator_name=creator_name)


def build_mii_official(mii: MiiOfficial) -> bytes:
    return build_mii_core(mii.core) + _encode_utf16_field(mii.creator_name, NAME_SIZE)
