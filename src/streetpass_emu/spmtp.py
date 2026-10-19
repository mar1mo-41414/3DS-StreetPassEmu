"""SPMTP: the StreetPass message layer carried inside SPTCP (sptcp.py).


HANDSHAKE_MAGIC, PacketType.IDENTITY_CLIENT, HandshakeHeader, and
IdentityPacket are now verified against a real captured Identity (client)
packet decrypted live from a real console -- parsed with zero errors,
content_size matching IdentityPacket.SIZE exactly.
Everything else here (TMP Box / Message Box, and every other packet type)
still only comes from the 3dbrew field tables with no real capture yet --
multi-byte integer fields are encoded little-endian by convention (the 3DS
is a little-endian ARM system, and that's what every other verified
StreetPass structure in this codebase uses, IdentityPacket included), but
that specific choice remains otherwise unverified for those. Confirm
against real captures before trusting byte-for-byte.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List

HANDSHAKE_HEADER_SIZE = 0x10
HANDSHAKE_MAGIC = 0x6363

TMP_BOX_MAGIC = 0x6161
MESSAGE_BOX_LIST_MAGIC = 0x6565

MESSAGE_BOX_METADATA_ENTRY_SIZE = 0x20
TMP_BOX_METADATA_ENTRY_SIZE = 0x8

IDENTITY_ACCEPT_SIZE = 0x10


class PacketType:
    """project findings "Packet Types" table."""

    IDENTITY_CLIENT = 0x41
    IDENTITY_MASTER = 0x42
    IDENTITY_ACCEPT = 0x43
    MODULE_FILTER_CLIENT = 0x11
    MODULE_FILTER_MASTER = 0x12
    FRIEND_CODE_CLIENT = 0x21
    FRIEND_CODE_MASTER = 0x22
    FRIEND_FLAG_CLIENT = 0x23
    FRIEND_FLAG_MASTER = 0x24
    MESSAGE_BOX_METADATA_LIST_CLIENT = 0x31
    MESSAGE_BOX_METADATA_LIST_MASTER = 0x32
    MESSAGE_BOX_METADATA_PARSED_CLIENT = 0x33
    MESSAGE_BOX_METADATA_PARSED_MASTER = 0x34
    TMP_BOX_METADATA_LIST = 0x81


# The fixed order every StreetPass conversation's handshake messages are sent
# in, alternating client/master.
HANDSHAKE_MESSAGE_ORDER = (
    PacketType.IDENTITY_CLIENT,
    PacketType.IDENTITY_MASTER,
    PacketType.IDENTITY_ACCEPT,
    PacketType.IDENTITY_ACCEPT,
    PacketType.MODULE_FILTER_CLIENT,
    PacketType.MODULE_FILTER_MASTER,
    PacketType.FRIEND_CODE_CLIENT,
    PacketType.FRIEND_CODE_MASTER,
    PacketType.FRIEND_FLAG_CLIENT,
    PacketType.FRIEND_FLAG_MASTER,
    PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT,
    PacketType.MESSAGE_BOX_METADATA_LIST_MASTER,
    PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT,
    PacketType.MESSAGE_BOX_METADATA_PARSED_MASTER,
    PacketType.TMP_BOX_METADATA_LIST,
    PacketType.TMP_BOX_METADATA_LIST,
)


@dataclass(frozen=True)
class HandshakeHeader:
    packet_type: int
    content_size: int


def parse_handshake_header(data: bytes) -> HandshakeHeader:
    if len(data) < HANDSHAKE_HEADER_SIZE:
        raise ValueError(f"data must be at least {HANDSHAKE_HEADER_SIZE} bytes, got {len(data)}")
    magic = int.from_bytes(data[0:2], "little")
    if magic != HANDSHAKE_MAGIC:
        raise ValueError(f"bad SPMTP handshake magic {magic:#06x}, expected {HANDSHAKE_MAGIC:#06x}")
    return HandshakeHeader(
        packet_type=int.from_bytes(data[4:8], "little"),
        content_size=int.from_bytes(data[12:16], "little"),
    )


def build_handshake_header(header: HandshakeHeader) -> bytes:
    return (
        HANDSHAKE_MAGIC.to_bytes(2, "little")
        + bytes(2)  # padding
        + header.packet_type.to_bytes(4, "little")
        + bytes(4)  # zero
        + header.content_size.to_bytes(4, "little")
    )


@dataclass(frozen=True)
class IdentityPacket:
    """0x41 (client) / 0x42 (master): project findings"""

    transferable_id: bytes  # 8 bytes
    session_id: int  # 4 bytes, random per session
    original_mac: bytes  # 6 bytes -- distinct from the continuous-scan MAC (dot11.py)
    timestamp: bytes  # 12 bytes; first 4 confirmed live as
    # year (u16 LE) + month (u8) + day (u8) -- matched the real capture date exactly.
    # Remaining 8 bytes still unconfirmed.
    unknown_8: bytes = field(default_factory=lambda: bytes(8))
    # offset 8:16, between transferable_id and session_id. Was randomized here
    # for a while as a live experiment (project findings candidate --
    # this was the one identity field that stayed constant across every
    # outbound send unless touched), but real-hardware retesting found it
    # made no difference either way. 2026-09-13: found the actual 3dbrew SPMTP
    # page (locally saved, WebFetch to the live site 403s) explicitly
    # documents this offset as "Zero" -- reverted to that authoritative value
    # now that the randomization experiment is a confirmed dead end.

    SIZE = 8 + 8 + 4 + 6 + 2 + 12  # 0x28

    def __post_init__(self) -> None:
        if len(self.transferable_id) != 8:
            raise ValueError(f"transferable_id must be 8 bytes, got {len(self.transferable_id)}")
        if len(self.original_mac) != 6:
            raise ValueError(f"original_mac must be 6 bytes, got {len(self.original_mac)}")
        if len(self.timestamp) != 12:
            raise ValueError(f"timestamp must be 12 bytes, got {len(self.timestamp)}")
        if len(self.unknown_8) != 8:
            raise ValueError(f"unknown_8 must be 8 bytes, got {len(self.unknown_8)}")


def parse_identity_packet(data: bytes) -> IdentityPacket:
    if len(data) != IdentityPacket.SIZE:
        raise ValueError(f"Identity packet body must be {IdentityPacket.SIZE} bytes, got {len(data)}")
    return IdentityPacket(
        transferable_id=data[0:8],
        unknown_8=data[8:16],
        session_id=int.from_bytes(data[16:20], "little"),
        original_mac=data[20:26],
        timestamp=data[28:40],
    )


def build_identity_packet(packet: IdentityPacket) -> bytes:
    return (
        packet.transferable_id
        + packet.unknown_8
        + packet.session_id.to_bytes(4, "little")
        + packet.original_mac
        + bytes(2)  # padding
        + packet.timestamp
    )


def build_identity_accept_packet() -> bytes:
    """0x43: "Garbage"  -- any 0x10 bytes are valid,
    zero is as good a placeholder as any until a real capture says otherwise."""
    return bytes(IDENTITY_ACCEPT_SIZE)


@dataclass(frozen=True)
class FriendCodePacket:
    friend_code: int  # 8 bytes

    def __post_init__(self) -> None:
        if not (0 <= self.friend_code < 2 ** 64):
            raise ValueError(f"friend_code must fit in 8 bytes, got {self.friend_code}")


def parse_friend_code_packet(data: bytes) -> FriendCodePacket:
    if len(data) != 8:
        raise ValueError(f"Friend Code packet body must be 8 bytes, got {len(data)}")
    return FriendCodePacket(friend_code=int.from_bytes(data, "little"))


def build_friend_code_packet(packet: FriendCodePacket) -> bytes:
    return packet.friend_code.to_bytes(8, "little")


def principal_id_checksum(principal_id: int) -> int:
    """The public (non-secret) Nintendo friend-code checksum formula: the
    low 7 bits of SHA-1(principal_id as 4 bytes LE)[0]. Not StreetPass-
    specific -- this is the same "principal ID -> friend code" scheme used
    across Wii/DS/3DS/WiiU/NEX-era online services (libctru's
    FRD_PrincipalIdToFriendCode()/FRD_FriendCodeToPrincipalId())."""
    digest = hashlib.sha1(principal_id.to_bytes(4, "little")).digest()
    return digest[0] >> 1


def friend_code_value_from_string(friend_code: str) -> int:
    """Parse a printable 12-digit friend code (with or without dashes, e.g.
    "4126-2228-0312") into the raw 64-bit value FriendCodePacket.friend_code
    (and libctru's `u64 friendCode`) actually holds: the checksum
    (principal_id_checksum()) in the high bits, the principal ID in the low
    32 bits. Raises ValueError if the checksum doesn't validate -- almost
    always a typo, since a real console never hands out an invalid one."""
    digits = friend_code.replace("-", "").replace(" ", "")
    if len(digits) != 12 or not digits.isdigit():
        raise ValueError(f"friend code must be 12 digits, got {friend_code!r}")
    value = int(digits)
    principal_id = value & 0xFFFFFFFF
    checksum = value >> 32
    if checksum != principal_id_checksum(principal_id):
        raise ValueError(f"friend code {friend_code!r} fails its own checksum -- check for a typo")
    return value


@dataclass(frozen=True)
class FriendFlagPacket:
    flag: int  # 4 bytes; whether the peer is on your friend list

    def __post_init__(self) -> None:
        if not (0 <= self.flag < 2 ** 32):
            raise ValueError(f"flag must fit in 4 bytes, got {self.flag}")


def parse_friend_flag_packet(data: bytes) -> FriendFlagPacket:
    if len(data) != 4:
        raise ValueError(f"Friend Flag packet body must be 4 bytes, got {len(data)}")
    return FriendFlagPacket(flag=int.from_bytes(data, "little"))


def build_friend_flag_packet(packet: FriendFlagPacket) -> bytes:
    return packet.flag.to_bytes(4, "little")


@dataclass(frozen=True)
class MessageBoxMetadataEntry:
    """project findings "Message Box Metadata Entry" (0x20 bytes)."""

    title_id: int  # 4 bytes
    send_mode: int  # 1 byte
    flag: int  # 1 byte
    send_state: int  # 2 bytes -- set by the peer when echoed back in 0x33/0x34
    send_size: int  # 4 bytes -- total size of all messages queued for this title
    message_count: int  # 4 bytes

    SIZE = MESSAGE_BOX_METADATA_ENTRY_SIZE


def parse_message_box_metadata_entry(data: bytes) -> MessageBoxMetadataEntry:
    if len(data) != MessageBoxMetadataEntry.SIZE:
        raise ValueError(f"entry must be {MessageBoxMetadataEntry.SIZE} bytes, got {len(data)}")
    return MessageBoxMetadataEntry(
        title_id=int.from_bytes(data[0:4], "little"),
        send_mode=data[4],
        flag=data[5],
        send_state=int.from_bytes(data[6:8], "little"),
        send_size=int.from_bytes(data[8:12], "little"),
        message_count=int.from_bytes(data[12:16], "little"),
    )


def build_message_box_metadata_entry(entry: MessageBoxMetadataEntry) -> bytes:
    return (
        entry.title_id.to_bytes(4, "little")
        + bytes([entry.send_mode, entry.flag])
        + entry.send_state.to_bytes(2, "little")
        + entry.send_size.to_bytes(4, "little")
        + entry.message_count.to_bytes(4, "little")
        + bytes(16)  # unused/reserved
    )


def parse_message_box_metadata_list(data: bytes) -> List[MessageBoxMetadataEntry]:
    """0x31-0x34: magic 0x6565, length, count, then `count` entries."""
    if len(data) < 0x2C:
        raise ValueError(f"data must be at least 0x2C bytes, got {len(data)}")
    magic = int.from_bytes(data[0:2], "little")
    if magic != MESSAGE_BOX_LIST_MAGIC:
        raise ValueError(f"bad Message Box list magic {magic:#06x}, expected {MESSAGE_BOX_LIST_MAGIC:#06x}")
    count = int.from_bytes(data[8:12], "little")
    entries_start = 0x2C
    entries_end = entries_start + count * MessageBoxMetadataEntry.SIZE
    if len(data) < entries_end:
        raise ValueError(f"data too short for {count} entries")
    return [
        parse_message_box_metadata_entry(data[i:i + MessageBoxMetadataEntry.SIZE])
        for i in range(entries_start, entries_end, MessageBoxMetadataEntry.SIZE)
    ]


def build_message_box_metadata_list(entries: List[MessageBoxMetadataEntry]) -> bytes:
    body = b"".join(build_message_box_metadata_entry(e) for e in entries)
    length = 0x2C + len(body)
    return (
        MESSAGE_BOX_LIST_MAGIC.to_bytes(2, "little")
        + bytes(2)  # padding
        + length.to_bytes(4, "little")
        + len(entries).to_bytes(4, "little")
        + bytes(0x20)  # unused/reserved
        + body
    )


@dataclass(frozen=True)
class TmpBoxMetadataEntry:
    """project findings "TMP Box Metadata Entry" (0x8 bytes)."""

    title_id: int  # 4 bytes
    size: int  # 4 bytes -- size of the TMP Box to be sent for this title

    SIZE = TMP_BOX_METADATA_ENTRY_SIZE


def parse_tmp_box_metadata_entry(data: bytes) -> TmpBoxMetadataEntry:
    if len(data) != TmpBoxMetadataEntry.SIZE:
        raise ValueError(f"entry must be {TmpBoxMetadataEntry.SIZE} bytes, got {len(data)}")
    return TmpBoxMetadataEntry(
        title_id=int.from_bytes(data[0:4], "little"),
        size=int.from_bytes(data[4:8], "little"),
    )


def build_tmp_box_metadata_entry(entry: TmpBoxMetadataEntry) -> bytes:
    return entry.title_id.to_bytes(4, "little") + entry.size.to_bytes(4, "little")


def parse_tmp_box_metadata_list(data: bytes) -> List[TmpBoxMetadataEntry]:
    """0x81: count (4 bytes) then `count` entries."""
    if len(data) < 4:
        raise ValueError(f"data must be at least 4 bytes, got {len(data)}")
    count = int.from_bytes(data[0:4], "little")
    entries_end = 4 + count * TmpBoxMetadataEntry.SIZE
    if len(data) < entries_end:
        raise ValueError(f"data too short for {count} entries")
    return [
        parse_tmp_box_metadata_entry(data[i:i + TmpBoxMetadataEntry.SIZE])
        for i in range(4, entries_end, TmpBoxMetadataEntry.SIZE)
    ]


TMP_BOX_METADATA_LIST_SLOT_COUNT = 24
"""project findings: a live capture of a real peer's own non-empty 0x81
decoded as content_size=0xc4 (196 = 4 + 24*8) with entry 0 = (title_id=
0x00020800, size=32712 -- exactly this project's known-good reference TMP
Box's total size) followed by 23 all-zero padding entries. So real hardware
pads a non-empty list out to this fixed slot count rather than sending just
`count` entries -- suspected of being the real cause behind a peer getting
stuck endlessly retransmitting window 1 of its own send after receiving our
previously-unpadded, much shorter reply (see §7.37 for the full writeup)."""


def build_tmp_box_metadata_list(entries: List[TmpBoxMetadataEntry]) -> bytes:
    body = b"".join(build_tmp_box_metadata_entry(e) for e in entries)
    if entries:
        pad_count = max(TMP_BOX_METADATA_LIST_SLOT_COUNT - len(entries), 0)
        body += bytes(TmpBoxMetadataEntry.SIZE * pad_count)
    return len(entries).to_bytes(4, "little") + body


TMP_BOX_HEADER_SIZE = 0x14


@dataclass(frozen=True)
class TmpBoxHeader:
    """project findings "TMP Box Packets" header. The message bytes that
    follow (CECD savegame Message/Slot structures) aren't parsed here yet --
    """

    size: int  # 4 bytes
    title_id: int  # 4 bytes
    group_id: int  # 4 bytes -- messages can be grouped by id
    message_count: int  # 4 bytes


def parse_tmp_box_header(data: bytes) -> TmpBoxHeader:
    if len(data) < TMP_BOX_HEADER_SIZE:
        raise ValueError(f"data must be at least {TMP_BOX_HEADER_SIZE} bytes, got {len(data)}")
    magic = int.from_bytes(data[0:2], "little")
    if magic != TMP_BOX_MAGIC:
        raise ValueError(f"bad TMP Box magic {magic:#06x}, expected {TMP_BOX_MAGIC:#06x}")
    return TmpBoxHeader(
        size=int.from_bytes(data[4:8], "little"),
        title_id=int.from_bytes(data[8:12], "little"),
        group_id=int.from_bytes(data[12:16], "little"),
        message_count=int.from_bytes(data[16:20], "little"),
    )


def build_tmp_box_header(header: TmpBoxHeader) -> bytes:
    return (
        TMP_BOX_MAGIC.to_bytes(2, "little")
        + bytes(2)  # padding
        + header.size.to_bytes(4, "little")
        + header.title_id.to_bytes(4, "little")
        + header.group_id.to_bytes(4, "little")
        + header.message_count.to_bytes(4, "little")
    )
