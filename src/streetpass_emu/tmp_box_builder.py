"""Builds a Mii Plaza StreetPass TMP Box from scratch (no genuine box needed as a template).

The layout below is the outcome of the project's analysis (docs/EN/PROTOCOL_REFERENCE.md has the detail).
Only what the receiver needs is modelled; everything else stays zero. The emulator test
(scripts/emu_bisect_box.py) showed that Mii Plaza accepts a box whose body is all zero apart
from the first 0x30 bytes and the sender Mii.

Message (32,692 bytes with the defaults)::

    0x0000  CecMessageHeader                  0x70
    0x0070  TLV id=2: header icon 40x40       8 + 3200
            TLV id=4: notification text       8 + 18      (+2 bytes padding -> 0xD14)
    0x0D14  body                              0x7280
            HMAC-SHA256 trailer               32          (key fixed, body only)

Body offsets (body-relative)::

    0x0000  title id u64, title version u16   "last title that touched the Mii"
    0x0010  u32 1, u32 0x80
    0x0030  SMDH Title[16] (0x200 each); [0] short name doubles as the title name at 0x30
    0x2038  small icon 24x24   0x24B8  large icon 48x48   (RGB565, PICA200 tiles)
    0x36B8  u32 0x100                           0x36BC  "CFPB" Mii database header
    0x36D4  sender Mii (112 B, AES-CCM)         0x4484  copy of the Mii's mii_id (10 B)
    0x375C  residence: byte 2 = region, byte 3 = country (1 = Japan)
    0x3760  country names 16x0x40               0x3B60  region names 16x0x40
    0x3F60  comment header (u32 counter, ...)   0x3F70  comment (16 chars, UTF-16LE)
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from . import icon
from .mii_qr import FFL_STORE_DATA_SIZE, MII_ID_OFFSET, decode_mii_blob, encode_mii_blob
from .smdh import TITLE_COUNT, TITLE_TABLE_SIZE, Title, build_title_table

MII_PLAZA_TITLE_ID = 0x00020800
MII_PLAZA_HMAC_KEY = b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl"

HEADER_FIXED = 0x70
HEADER_ICON_SIZE = 3200
NOTICE_BYTES = 18
BODY_SIZE = 0x7280
TRAILER_SIZE = 32

OFF_TITLE_ID = 0x00
OFF_TITLE_VERSION = 0x08
OFF_TITLE_TABLE = 0x30
OFF_SMALL_ICON = 0x2038
OFF_LARGE_ICON = 0x24B8
OFF_MII_DB_PREFACE = 0x36B8
OFF_MII_DB_HEADER = 0x36BC
OFF_MII = 0x36D4
OFF_RESIDENCE = 0x375C
OFF_COUNTRY_NAMES = 0x3760
OFF_REGION_NAMES = 0x3B60
OFF_COMMENT_HEADER = 0x3F60
OFF_MII_ID_COPY = 0x4484
OFF_COMMENT = 0x3F70
NAME_ENTRY = 0x40
COMMENT_MAX_CHARS = 16

# CecMessageHeader defaults seen in every genuine Mii Plaza box
DEFAULT_FLAGS = 3
DEFAULT_SEND_COUNT = 0xFF
DEFAULT_FORWARD_COUNT = 1

# "the last title that touched the sender's Mii": System Settings v12.0.1
DEFAULT_APP_TITLE_ID = 0x0004001000020000
DEFAULT_APP_TITLE_VERSION = 0x3001


# CecMessageHeader fields (name, offset, length), see docs/EN/PROTOCOL_REFERENCE.md. ``BoxSpec.header_fields``
# can override any of them by offset.
HEADER_FIELDS = [
    ("titleId2", 0x14, 4), ("batchId", 0x18, 4), ("unknown1", 0x1C, 4), ("messageId", 0x20, 8),
    ("messageVersion", 0x28, 4), ("messageId2", 0x2C, 8), ("flags", 0x34, 1), ("sendMethod", 0x35, 1),
    ("unopened", 0x36, 1), ("newFlag", 0x37, 1), ("senderId", 0x38, 8), ("senderId2", 0x40, 8),
    ("sendTime", 0x48, 12), ("recvTime", 0x54, 12), ("created", 0x60, 12), ("sendCount", 0x6C, 1),
    ("forwardCount", 0x6D, 1), ("userData", 0x6E, 2),
]

# body ranges the builder fills from BoxSpec fields; anything non-zero outside them in a parsed box
# is kept verbatim in ``extra_body`` so that a loaded box can be rebuilt byte for byte.
MODELLED_BODY_RANGES = [
    (0x0000, 0x0018), (OFF_TITLE_TABLE, OFF_TITLE_TABLE + TITLE_TABLE_SIZE),
    (OFF_SMALL_ICON, OFF_LARGE_ICON + 4608), (OFF_MII_DB_PREFACE, OFF_MII + 112),
    (OFF_RESIDENCE, OFF_COMMENT + (COMMENT_MAX_CHARS + 1) * 2), (OFF_MII_ID_COPY, OFF_MII_ID_COPY + 10),
]


@dataclass
class BoxSpec:
    """Everything that varies between boxes. Only ``mii`` is mandatory."""

    mii: bytes                                     # 96-byte FFLStoreData of the sender
    comment: str = ""                              # greeting, up to 16 chars
    notice: str = "誰か来ています!"                # TLV id=4 text (up to 8 chars)
    header_icon: Optional[bytes] = None            # 3200 B tiled RGB565 (default: blank)
    app_title_id: int = DEFAULT_APP_TITLE_ID
    app_title_version: int = DEFAULT_APP_TITLE_VERSION
    titles: Optional[list[Title]] = None           # SMDH Title[16] (padded with the last one)
    small_icon: Optional[bytes] = None             # 1152 B
    large_icon: Optional[bytes] = None             # 4608 B
    country: int = 0                               # 1 = Japan, 0 = not set
    region: int = 0
    country_names: Optional[list[str]] = None      # 16 languages
    region_names: Optional[list[str]] = None       # 16 languages
    mii_id_copy: Optional[bytes] = None            # 10 B at 0x4484; default: the Mii's own mii_id
    visit_counter: int = 1                         # u32 at 0x3F60 (monotonic on a real console)
    comment_header_tail: bytes = bytes(12)         # 0x3F64..0x3F70, meaning unknown
    message_id: Optional[bytes] = None             # 8 bytes, random by default
    created: Optional[datetime.datetime] = None    # default: now
    extra_body: dict[int, bytes] = field(default_factory=dict)  # body offset -> bytes (unmodelled areas)
    header_fields: dict[int, bytes] = field(default_factory=dict)  # header offset -> bytes (overrides)


def _timestamp(dt: datetime.datetime) -> bytes:
    weekday = (dt.weekday() + 1) % 7  # CTR weeks start on Sunday
    return struct.pack("<IBBBBBBH", dt.year, dt.month, dt.day, weekday,
                       dt.hour, dt.minute, dt.second, dt.microsecond // 1000)


def _utf16_fixed(text: str, size: int) -> bytes:
    raw = text.encode("utf-16le")
    if len(raw) > size - 2:
        raise ValueError(f"{text!r} does not fit in {size} bytes (needs a NUL terminator)")
    return raw + bytes(size - len(raw))


def _name_table(names: Optional[list[str]]) -> bytes:
    if not names:
        return bytes(NAME_ENTRY * TITLE_COUNT)
    if len(names) > TITLE_COUNT:
        raise ValueError("at most 16 names")
    padded = names + [names[-1]] * (TITLE_COUNT - len(names))
    return b"".join(_utf16_fixed(n, NAME_ENTRY) for n in padded)


def build_body(spec: BoxSpec) -> bytes:
    body = bytearray(BODY_SIZE)

    def put(off: int, data: bytes) -> None:
        body[off:off + len(data)] = data

    struct.pack_into("<QH", body, OFF_TITLE_ID, spec.app_title_id, spec.app_title_version)
    struct.pack_into("<II", body, 0x10, 1, 0x80)

    titles = spec.titles or [Title("StreetPass", "", "")]
    put(OFF_TITLE_TABLE, build_title_table(titles))
    assert len(build_title_table(titles)) == TITLE_TABLE_SIZE

    if spec.small_icon is not None:
        if len(spec.small_icon) != icon.icon_bytes(icon.SMALL_SIZE):
            raise ValueError("small icon must be 1152 bytes")
        put(OFF_SMALL_ICON, spec.small_icon)
    if spec.large_icon is not None:
        if len(spec.large_icon) != icon.icon_bytes(icon.LARGE_SIZE):
            raise ValueError("large icon must be 4608 bytes")
        put(OFF_LARGE_ICON, spec.large_icon)

    if len(spec.mii) != FFL_STORE_DATA_SIZE:
        raise ValueError(f"mii must be {FFL_STORE_DATA_SIZE} bytes (FFLStoreData)")
    struct.pack_into("<I", body, OFF_MII_DB_PREFACE, 0x100)
    put(OFF_MII_DB_HEADER, b"CFPB" + struct.pack("<5I", 1, 0, 0, 0, 1))
    put(OFF_MII, encode_mii_blob(spec.mii))

    put(OFF_MII_ID_COPY, spec.mii_id_copy if spec.mii_id_copy is not None
        else spec.mii[MII_ID_OFFSET:MII_ID_OFFSET + 10])  # genuine boxes repeat the mii_id here
    body[OFF_RESIDENCE + 2] = spec.region
    body[OFF_RESIDENCE + 3] = spec.country
    put(OFF_COUNTRY_NAMES, _name_table(spec.country_names))
    put(OFF_REGION_NAMES, _name_table(spec.region_names))

    if len(spec.comment) > COMMENT_MAX_CHARS:
        raise ValueError(f"comment must be at most {COMMENT_MAX_CHARS} characters")
    if len(spec.comment_header_tail) != 12:
        raise ValueError("comment_header_tail must be 12 bytes")
    put(OFF_COMMENT_HEADER, struct.pack("<I", spec.visit_counter) + spec.comment_header_tail)
    put(OFF_COMMENT, _utf16_fixed(spec.comment, (COMMENT_MAX_CHARS + 1) * 2))

    for off, data in spec.extra_body.items():
        put(off, data)
    return bytes(body)


def build_message(spec: BoxSpec) -> bytes:
    """The bare message (magic 0x6060), as stored in the CEC InBox/OutBox."""
    icon_data = spec.header_icon if spec.header_icon is not None else bytes(HEADER_ICON_SIZE)
    if len(icon_data) != HEADER_ICON_SIZE:
        raise ValueError(f"header icon must be {HEADER_ICON_SIZE} bytes")
    notice = _utf16_fixed(spec.notice, NOTICE_BYTES)
    tlv = (struct.pack("<II", 2, HEADER_ICON_SIZE) + icon_data
           + struct.pack("<II", 4, NOTICE_BYTES) + notice)
    header_size = HEADER_FIXED + len(tlv)
    header_size += -header_size % 4          # genuine boxes pad 0xD12 up to 0xD14
    tlv += bytes(header_size - HEADER_FIXED - len(tlv))

    body = build_body(spec)
    message_size = header_size + len(body) + TRAILER_SIZE
    mid = spec.message_id if spec.message_id is not None else os.urandom(8)
    if len(mid) != 8:
        raise ValueError("message_id must be 8 bytes")
    created = _timestamp(spec.created or datetime.datetime.now())

    head = bytearray(HEADER_FIXED)
    struct.pack_into("<HHIII", head, 0, 0x6060, 0, message_size, header_size, len(body))
    struct.pack_into("<I", head, 0x10, MII_PLAZA_TITLE_ID)
    head[0x20:0x28] = mid
    head[0x34] = DEFAULT_FLAGS
    head[0x60:0x6C] = created
    head[0x6C] = DEFAULT_SEND_COUNT
    head[0x6D] = DEFAULT_FORWARD_COUNT
    for off, data in spec.header_fields.items():
        if not 0x14 <= off < HEADER_FIXED or off + len(data) > HEADER_FIXED:
            raise ValueError(f"header field at {off:#x}+{len(data)} is outside the fixed header")
        head[off:off + len(data)] = data

    trailer = hmac.new(MII_PLAZA_HMAC_KEY, body, hashlib.sha256).digest()
    return bytes(head) + tlv + body + trailer


def mii_from_blob_or_raw(data: bytes) -> bytes:
    """Accepts a raw 96-byte FFLStoreData or a 112-byte encrypted Mii blob / QR payload."""
    if len(data) == FFL_STORE_DATA_SIZE:
        return data
    if len(data) >= 108:
        return decode_mii_blob(data)
    raise ValueError(f"expected 96 (FFLStoreData) or 112 (encrypted) bytes, got {len(data)}")


def _read_names(data: bytes) -> list[str]:
    return [data[i:i + NAME_ENTRY].decode("utf-16le").rstrip("\x00")
            for i in range(0, NAME_ENTRY * TITLE_COUNT, NAME_ENTRY)]


def spec_from_message(msg: bytes) -> BoxSpec:
    """Reads the modelled fields out of a genuine (or built) message; the inverse of build_message.

    Used for the round-trip test: build_message(spec_from_message(real)) differs from the real
    box only in what the builder does not model yet.
    """
    from .smdh import parse_title_table

    magic, _p, _msize, hsize, bsize = struct.unpack_from("<HHIII", msg, 0)
    if magic != 0x6060:
        raise ValueError("not a TMP Box message")
    tlvs, off = {}, HEADER_FIXED
    while off + 8 <= hsize:
        tid, tlen = struct.unpack_from("<II", msg, off)
        if tid not in (2, 4) or off + 8 + tlen > hsize:
            break
        tlvs[tid] = msg[off + 8:off + 8 + tlen]
        off += 8 + tlen
    b = msg[hsize:hsize + bsize]
    title_id, title_ver = struct.unpack_from("<QH", b, OFF_TITLE_ID)
    ts = struct.unpack_from("<IBBBBBBH", msg, 0x60)
    created = datetime.datetime(ts[0], ts[1], ts[2], ts[4], ts[5], ts[6], ts[7] * 1000)
    unmodelled = {}
    mask = bytearray(len(b))
    for a, z in MODELLED_BODY_RANGES:
        mask[a:z] = b"\x01" * (z - a)
    i = 0
    while i < len(b):
        if mask[i] or not b[i]:
            i += 1
            continue
        j = i
        while j < len(b) and not mask[j] and (b[j] or any(b[j:j + 16])):
            j += 1
        j = min(j, len(b))
        unmodelled[i] = bytes(b[i:j].rstrip(b"\x00")) or bytes(b[i:j])
        i = j
    return BoxSpec(
        header_fields={off: bytes(msg[off:off + n]) for _name, off, n in HEADER_FIELDS},
        extra_body=unmodelled,
        mii=decode_mii_blob(b[OFF_MII:OFF_MII + 112]),
        comment=b[OFF_COMMENT:OFF_COMMENT + (COMMENT_MAX_CHARS + 1) * 2].decode("utf-16le").split("\x00")[0],
        notice=tlvs[4].decode("utf-16le").rstrip("\x00"),
        header_icon=tlvs[2],
        app_title_id=title_id, app_title_version=title_ver,
        titles=parse_title_table(b[OFF_TITLE_TABLE:OFF_TITLE_TABLE + TITLE_TABLE_SIZE]),
        small_icon=b[OFF_SMALL_ICON:OFF_SMALL_ICON + icon.icon_bytes(icon.SMALL_SIZE)],
        large_icon=b[OFF_LARGE_ICON:OFF_LARGE_ICON + icon.icon_bytes(icon.LARGE_SIZE)],
        country=b[OFF_RESIDENCE + 3], region=b[OFF_RESIDENCE + 2],
        country_names=_read_names(b[OFF_COUNTRY_NAMES:OFF_COUNTRY_NAMES + NAME_ENTRY * TITLE_COUNT]),
        region_names=_read_names(b[OFF_REGION_NAMES:OFF_REGION_NAMES + NAME_ENTRY * TITLE_COUNT]),
        mii_id_copy=bytes(b[OFF_MII_ID_COPY:OFF_MII_ID_COPY + 10]),
        visit_counter=struct.unpack_from("<I", b, OFF_COMMENT_HEADER)[0],
        comment_header_tail=bytes(b[OFF_COMMENT_HEADER + 4:OFF_COMMENT_HEADER + 16]),
        message_id=bytes(msg[0x20:0x28]),
        created=created,
    )
