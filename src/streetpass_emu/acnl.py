"""Animal Crossing: New Leaf (とびだせ どうぶつの森 / amiibo+) StreetPass messages, kind 1: "house + player".

Layout (verified byte for byte against a message the game itself had queued in the console's CEC outbox, see
docs/EN/GAME_FORMATS.md §3): the standard CecMessageHeader (0x70 bytes) with ``batch_id`` 1 and ``user_data`` 1,
a header icon TLV (id 2, 3200 B) and a text TLV (id 4, UTF-16LE), then the body (0x7DC8 bytes), then a
32-byte HMAC-SHA256 trailer over the body (key below, from the title's mailbox info).

Body::

    0x0000  u32   magic 0x0700009E
    0x0004  u32   CRC-32C (Castagnoli) of 0x0008..0x7DC8-8
    0x0008  8 B   sender id (halves of the console's Mii author id, swapped)
    0x0010  0x1228  house data   = save file ``garden_plus.dat`` at 0x5D900 + 0x1228 * player
    0x1238  0x6B88  player data  = save file at 0xA0 + 0x9F10 * player (the first 0x6B88 bytes; only player 0 checked)
    0x7DC0  8 B   = save file at 0x6E29A

Inside the player data: +0x55A6 player id (u16), +0x55A8 player name (UTF-16LE, 10 chars), +0x55BC town id (u16),
+0x55BE town name (UTF-16LE, 9 chars). A receiving game ignores a message from its own town (it compares these).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

ACNL_TITLE_ID = 0x00198D00
ACNL_HMAC_KEY = b"ne2seon7xy1ars3duofzxjbmykufd0n8"   # from the title's CecMBoxInfoHeader; verified on a real message

MAGIC = 0x0700009E
HEADER_FIXED = 0x70
ICON_SIZE = 3200
HOUSE_SIZE = 0x1228
PLAYER_SIZE = 0x6B88
BODY_SIZE = 0x7DC8
TRAILER_SIZE = 32
HEADER_PLAYER = 0x55A6

SAVE_PLAYER_BASE, SAVE_PLAYER_STRIDE = 0xA0, 0x9F10
SAVE_HOUSE_BASE = 0x5D900
SAVE_TAIL = 0x6E29A


def _crc32c_table() -> list[int]:
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
        t.append(c)
    return t


_T = _crc32c_table()


def crc32c(data: bytes) -> int:
    c = 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def _utf16(text: str) -> bytes:
    return text.encode("utf-16le")


@dataclass
class AcnlHouseMessage:
    id64: bytes                                   # body 0x08
    house: bytes                                  # 0x1228
    player: bytes                                 # 0x6B88
    tail: bytes = bytes(8)                        # body 0x7DC0
    notice: str = ""                              # TLV 4 text, e.g. "<town>\n<player>'s model house"
    icon: Optional[bytes] = None                  # TLV 2, 3200 B (default: grey placeholder)
    message_id: Optional[bytes] = None
    created: Optional[datetime.datetime] = None
    header_fields: dict[int, bytes] = field(default_factory=dict)   # header offset -> bytes (overrides)

    # ---- parsed views of the player data ----------------------------------------------------
    @property
    def player_id(self) -> int:
        return struct.unpack_from("<H", self.player, HEADER_PLAYER)[0]

    @property
    def player_name(self) -> str:
        return self.player[0x55A8:0x55A8 + 20].decode("utf-16le", "replace").split("\0")[0]

    @property
    def town_id(self) -> int:
        return struct.unpack_from("<H", self.player, 0x55BC)[0]

    @property
    def town_name(self) -> str:
        return self.player[0x55BE:0x55BE + 18].decode("utf-16le", "replace").split("\0")[0]

    # ---- build ----------------------------------------------------------------------------
    def body(self) -> bytes:
        if len(self.id64) != 8 or len(self.tail) != 8:
            raise ValueError("id64 and tail must be 8 bytes")
        if len(self.house) != HOUSE_SIZE or len(self.player) != PLAYER_SIZE:
            raise ValueError(f"house must be {HOUSE_SIZE} and player {PLAYER_SIZE} bytes")
        inner = self.id64 + self.house + self.player + self.tail
        return struct.pack("<II", MAGIC, crc32c(inner)) + inner

    def build(self) -> bytes:
        icon = self.icon if self.icon is not None else _placeholder_icon()
        if len(icon) != ICON_SIZE:
            raise ValueError(f"icon must be {ICON_SIZE} bytes")
        text = _utf16(self.notice)
        tlv = struct.pack("<II", 2, ICON_SIZE) + icon + struct.pack("<II", 4, len(text)) + text
        header_size = HEADER_FIXED + len(tlv)
        header_size += -header_size % 4
        tlv += bytes(header_size - HEADER_FIXED - len(tlv))
        body = self.body()
        head = bytearray(HEADER_FIXED)
        struct.pack_into("<HHIII", head, 0, 0x6060, 0, header_size + len(body) + TRAILER_SIZE, header_size, len(body))
        struct.pack_into("<I", head, 0x10, ACNL_TITLE_ID)
        struct.pack_into("<I", head, 0x18, 1)                        # batch / group id
        head[0x20:0x28] = self.message_id if self.message_id is not None else os.urandom(8)
        head[0x34] = head[0x35] = 3
        now = self.created or datetime.datetime.now()
        head[0x60:0x6C] = struct.pack("<IBBBBBBH", now.year, now.month, now.day, (now.weekday() + 1) % 7,
                                      now.hour, now.minute, now.second, now.microsecond // 1000)
        head[0x6C] = 0xFF                                            # sendCount (0xFF marks a house message)
        head[0x6D] = 1                                               # forwardCount
        struct.pack_into("<H", head, 0x6E, 1)                        # userData 1 = house + player
        for off, data in self.header_fields.items():
            head[off:off + len(data)] = data
        trailer = hmac.new(ACNL_HMAC_KEY, body, hashlib.sha256).digest()
        return bytes(head) + tlv + body + trailer


def _placeholder_icon() -> bytes:
    from . import icon
    return icon.placeholder(icon.TLV_SIZE)


IDENTITY_OFFSET = 0x55A6      # in the player data: player id (2) + name (20) + town id (2) + town name (18)
IDENTITY_SIZE = 2 + 20 + 2 + 18


def retarget_identity(player: bytes, *, player_id: int, player_name: str, town_id: int, town_name: str) -> bytes:
    """Rewrites who the player data says it is from: player id, name, town id and town name. The block appears once at
    ``+0x55A6`` and again in each design pattern (every pattern stores its creator), so every copy of the original block
    is replaced to keep the data self-consistent. A game ignores a message from its own town, so a message that is
    to be accepted needs a town id / town name that differ from the receiver's. Names are limited to 8 characters."""
    if len(player) != PLAYER_SIZE:
        raise ValueError(f"player must be {PLAYER_SIZE} bytes")
    if not (0 <= player_id <= 0xFFFF and 0 <= town_id <= 0xFFFF):
        raise ValueError("player_id and town_id are 16-bit")
    if not (1 <= len(player_name) <= 8 and 1 <= len(town_name) <= 8):
        raise ValueError("player and town names are 1 to 8 characters")
    old = player[IDENTITY_OFFSET:IDENTITY_OFFSET + IDENTITY_SIZE]
    new = (struct.pack("<H", player_id) + _utf16(player_name).ljust(20, b"\0")
           + struct.pack("<H", town_id) + _utf16(town_name).ljust(18, b"\0"))
    out, pos, hits = bytearray(player), 0, 0
    while (i := player.find(old, pos)) != -1:
        out[i:i + IDENTITY_SIZE] = new
        pos, hits = i + IDENTITY_SIZE, hits + 1
    if hits == 0:
        raise ValueError("identity block not found")
    return bytes(out)


def wrap_tmp_box(message: bytes, group_id: int = 1, message_count: int = 1) -> bytes:
    """A message with the 0x14-byte TmpBoxHeader in front: what travels over the air (the genuine box has group id 1)."""
    from . import spmtp
    head = spmtp.build_tmp_box_header(spmtp.TmpBoxHeader(
        size=spmtp.TMP_BOX_HEADER_SIZE + len(message), title_id=ACNL_TITLE_ID, group_id=group_id,
        message_count=message_count))
    return head + message


@dataclass
class Parsed:
    message: AcnlHouseMessage
    magic_ok: bool
    crc_ok: bool
    hmac_ok: bool
    user_data: int


def parse_message(data: bytes) -> Parsed:
    """Reads a kind-1 message (a bare 0x6060 message; strip a 0x14-byte TmpBoxHeader first)."""
    if len(data) > 0x14 and struct.unpack_from("<H", data, 0)[0] == 0x6161:
        data = data[0x14:]
    magic, _p, msize, hsize, bsize = struct.unpack_from("<HHIII", data, 0)
    if magic != 0x6060 or struct.unpack_from("<I", data, 0x10)[0] != ACNL_TITLE_ID:
        raise ValueError("not an Animal Crossing: New Leaf message")
    user_data = struct.unpack_from("<H", data, 0x6E)[0]
    if bsize != BODY_SIZE:
        raise ValueError(f"body is {bsize} bytes, kind 1 has {BODY_SIZE} (userData={user_data})")
    tlvs, off = {}, HEADER_FIXED
    while off + 8 <= hsize:
        tid, tlen = struct.unpack_from("<II", data, off)
        if tid not in (2, 4) or off + 8 + tlen > hsize:
            break
        tlvs[tid] = data[off + 8:off + 8 + tlen]
        off += 8 + tlen
    body = data[hsize:hsize + bsize]
    inner = body[8:]
    msg = AcnlHouseMessage(
        id64=body[8:16], house=body[0x10:0x10 + HOUSE_SIZE], player=body[0x10 + HOUSE_SIZE:0x10 + HOUSE_SIZE + PLAYER_SIZE],
        tail=body[BODY_SIZE - 8:], notice=tlvs.get(4, b"").decode("utf-16le", "replace"), icon=tlvs.get(2),
        message_id=bytes(data[0x20:0x28]))
    ts = struct.unpack_from("<IBBBBBBH", data, 0x60)
    try:
        msg.created = datetime.datetime(ts[0], ts[1], ts[2], ts[4], ts[5], ts[6], ts[7] * 1000)
    except ValueError:
        pass
    trailer = data[hsize + bsize:hsize + bsize + TRAILER_SIZE]
    return Parsed(msg, struct.unpack_from("<I", body, 0)[0] == MAGIC, struct.unpack_from("<I", body, 4)[0] == crc32c(inner),
                  hmac.new(ACNL_HMAC_KEY, body, hashlib.sha256).digest() == trailer, user_data)


def from_save(save: bytes, id64: bytes, player: int = 0, notice: str = "", **kw) -> AcnlHouseMessage:
    """Builds a message from an ACNL save file (``garden_plus.dat``). ``id64`` is the sending console's id (8 bytes,
    not stored in the save). Only player 0 has been checked against a real message."""
    p0 = SAVE_PLAYER_BASE + SAVE_PLAYER_STRIDE * player
    h0 = SAVE_HOUSE_BASE + HOUSE_SIZE * player
    msg = AcnlHouseMessage(id64=id64, house=save[h0:h0 + HOUSE_SIZE], player=save[p0:p0 + PLAYER_SIZE],
                           tail=save[SAVE_TAIL:SAVE_TAIL + 8], notice=notice, **kw)
    if not notice:
        msg.notice = f"{msg.town_name}\n{msg.player_name}"
    return msg
