"""SPTCP: the layer-2 (MAC-only, no IP) TCP-like transport StreetPass's
post-handshake encrypted conversation runs over, carrying SPMTP messages
(see spmtp.py). 

This operates on already-decrypted CCMP payload bytes -- it has nothing to
do with 802.11 framing (dot11.py) or the WPA2 CCMP layer itself (crypto.py).
"""

from __future__ import annotations

from dataclasses import dataclass

# The decrypted CCMP payload (MSDU) carries this fixed 10-byte prefix before
# the SPTCP header proper starts -- looks like an 802.2 LLC/SNAP
# encapsulation (DSAP/SSAP=0xAA, Control=0x03, OUI=000000, EtherType=0x0800)
# plus 2 further unexplained bytes. Confirmed on every real captured SPTCP
# SYN packet so far; NOT yet confirmed for other
# SPTCP/SPMTP packet types, so treat this as handshake-packet-only until a
# real capture of something else shows the same prefix.
MSDU_PREAMBLE = bytes.fromhex("aaaa030000000800") + bytes(2)

MAGIC = 0x5959
# The 4 bytes at offset 0x4, in on-the-wire order. 3dbrew labels this
# "Constant (0xaddeafbe)" -- that's the raw byte sequence AD DE AF BE, not an
# integer to encode (confirmed against the real capture in §7.2: encoding it
# as a little-endian 0xADDEAFBE would emit BE AF DE AD instead).
CONSTANT = bytes.fromhex("addeafbe")
HEADER_SIZE = 0x18
DEFAULT_BUFFER_SIZE = 0x38B8

# project findings: "(Header size (0x18) + 0x18) right shifted 2 places
# (this is always 0x0c)" -- a fixed value, not dependent on payload size.
_SHIFTED_SIZE_FIELD = (HEADER_SIZE + 0x18) >> 2

FLAG_FIN = 1 << 0
FLAG_SYN = 1 << 1
FLAG_RST = 1 << 2
FLAG_PSH = 1 << 3
FLAG_ACK = 1 << 4
FLAG_END = 1 << 5


@dataclass(frozen=True)
class SptcpHeader:
    total_size: int  # header (0x18) + payload size + 0x18, 
    bytes_sent: int
    bytes_received: int
    flags: int
    max_buffer_size: int = DEFAULT_BUFFER_SIZE


def parse_header(data: bytes) -> SptcpHeader:
    if len(data) < HEADER_SIZE:
        raise ValueError(f"data must be at least {HEADER_SIZE} bytes, got {len(data)}")

    magic = int.from_bytes(data[0:2], "little")
    if magic != MAGIC:
        raise ValueError(f"bad SPTCP magic {magic:#06x}, expected {MAGIC:#06x}")

    constant = data[4:8]
    if constant != CONSTANT:
        raise ValueError(f"bad SPTCP constant {constant.hex()}, expected {CONSTANT.hex()}")

    shifted = data[16]
    if shifted != _SHIFTED_SIZE_FIELD:
        raise ValueError(f"bad SPTCP shifted-size field {shifted:#04x}, expected {_SHIFTED_SIZE_FIELD:#04x}")

    padding = data[20:24]
    if padding != bytes(4):
        raise ValueError(f"non-zero SPTCP padding: {padding.hex()}")

    return SptcpHeader(
        total_size=int.from_bytes(data[2:4], "little"),
        bytes_sent=int.from_bytes(data[8:12], "little"),
        bytes_received=int.from_bytes(data[12:16], "little"),
        flags=data[17],
        max_buffer_size=int.from_bytes(data[18:20], "little"),
    )


def payload_size(header: SptcpHeader) -> int:
    """The SPMTP payload length implied by total_size (the "header (0x18) +
    payload size + 0x18" formula) -- 0 for a bare
    handshake packet."""
    return header.total_size - 2 * HEADER_SIZE


def parse_packet(data: bytes) -> "tuple[SptcpHeader, bytes]":
    """parse_header() plus slicing out the SPMTP payload that follows it, per
    payload_size(). Confirmed against a real captured Identity-carrying
    packet, project findings"""
    header = parse_header(data)
    size = payload_size(header)
    payload = data[HEADER_SIZE:HEADER_SIZE + size]
    if len(payload) != size:
        raise ValueError(f"SPTCP payload truncated: total_size implies {size} bytes, got {len(payload)}")
    return header, payload


def build_header(header: SptcpHeader) -> bytes:
    return (
        MAGIC.to_bytes(2, "little")
        + header.total_size.to_bytes(2, "little")
        + CONSTANT
        + header.bytes_sent.to_bytes(4, "little")
        + header.bytes_received.to_bytes(4, "little")
        + bytes([_SHIFTED_SIZE_FIELD, header.flags])
        + header.max_buffer_size.to_bytes(2, "little")
        + bytes(4)
    )


def build_packet(
    flags: int,
    payload: bytes = b"",
    *,
    bytes_sent: int = 0,
    bytes_received: int = 0,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> bytes:
    """A general SPTCP packet, optionally carrying an SPMTP payload. bytes_sent/bytes_received stay 0 for a
    single-packet (unfragmented) message -- confirmed on a real captured
    Identity-carrying packet, project findings; only relevant once a
    message needs to span multiple packets, which isn't implemented here."""
    header = build_header(SptcpHeader(
        total_size=HEADER_SIZE + len(payload) + HEADER_SIZE,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        flags=flags,
        max_buffer_size=buffer_size,
    ))
    return header + payload


def build_handshake_packet(flags: int, buffer_size: int = DEFAULT_BUFFER_SIZE) -> bytes:
    """A SYN / SYN+ACK / ACK packet for the 3-way handshake -- these carry no SPMTP payload, so total_size is just 2*HEADER_SIZE."""
    return build_packet(flags, buffer_size=buffer_size)
