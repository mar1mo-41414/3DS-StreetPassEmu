"""WPA2 CCMP encrypt/decrypt for StreetPass's 802.11 Data frames.

This is the layer between raw 802.11 frames (dot11.py) and the plaintext
SPTCP/SPMTP conversation (sptcp.py/spmtp.py): given the session key
crypto.py derives, it turns a received protected Data frame into plaintext
(with MIC verification) and turns outgoing plaintext into a protected Data
frame to transmit.

Nonce/AAD construction verified end-to-end against real captured StreetPass
traffic -- 18 real CCMP frames from a real console, MIC matched, independently repeated on the AAD's Retry/
PwrMgmt/MoreData masking specifically (§3.4.8, a real retried frame's MIC
only matched once those bits were zeroed out of the AAD -- the mistake this
module has to not repeat).
"""

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES

from . import dot11

CCMP_HEADER_SIZE = 8
MIC_SIZE = 8
EXT_IV_FLAG = 0x20
PN_MAX = (1 << 48) - 1

# Retry, PwrMgmt, MoreData bits of frame_control -- excluded from the AAD by
# the 802.11 CCMP spec (so a retransmission's MIC still matches the
# original), zeroed out here regardless of what's actually set on the wire.
_AAD_FC_MASK = ~(0x0800 | 0x1000 | 0x2000) & 0xFFFF


class CcmpError(ValueError):
    """A frame isn't a well-formed protected Data frame, or its MIC didn't verify."""


@dataclass(frozen=True)
class DecryptedDataFrame:
    plaintext: bytes
    pn: int
    src: bytes
    dest: bytes


def _pn_to_ccmp_header(pn: int) -> bytes:
    if not 0 <= pn <= PN_MAX:
        raise ValueError(f"pn must fit in 48 bits, got {pn}")
    pn5, pn4, pn3, pn2, pn1, pn0 = pn.to_bytes(6, "big")
    return bytes([pn0, pn1, 0x00, EXT_IV_FLAG, pn2, pn3, pn4, pn5])


def _ccmp_header_to_pn(ccmp_header: bytes) -> int:
    pn0, pn1, _reserved, _key_id, pn2, pn3, pn4, pn5 = ccmp_header
    return (pn5 << 40) | (pn4 << 32) | (pn3 << 24) | (pn2 << 16) | (pn1 << 8) | pn0


def _aad(header: dot11.ManagementFrameHeader) -> bytes:
    fc_masked = header.frame_control & _AAD_FC_MASK
    sc_masked = header.seq_ctrl & 0x000F  # fragment number kept, sequence number zeroed
    return (
        fc_masked.to_bytes(2, "little")
        + header.addr1 + header.addr2 + header.addr3
        + sc_masked.to_bytes(2, "little")
    )


def _nonce(source_addr: bytes, pn: int) -> bytes:
    return bytes([0]) + source_addr + pn.to_bytes(6, "big")  # priority=0 (non-QoS)


def decrypt_data_frame(dot11_frame: bytes, key: bytes) -> DecryptedDataFrame:
    """Decrypt a protected 802.11 Data frame (no radiotap header), verifying
    its MIC. Raises CcmpError if it isn't one, is malformed, or the MIC
    doesn't check out."""
    if len(dot11_frame) < dot11.MGMT_HEADER_SIZE:
        raise CcmpError(f"frame too short ({len(dot11_frame)} bytes) to have an 802.11 header")

    header = dot11.parse_management_header(dot11_frame)
    if dot11.frame_type(header.frame_control) != dot11.FRAME_TYPE_DATA:
        raise CcmpError(f"not a Data frame (frame_control={header.frame_control:#06x})")
    if not dot11.is_protected(header.frame_control):
        raise CcmpError("Data frame is not protected (no CCMP)")

    body = dot11_frame[dot11.MGMT_HEADER_SIZE:]
    if len(body) < CCMP_HEADER_SIZE + MIC_SIZE:
        raise CcmpError(f"body too short ({len(body)} bytes) for a CCMP header + MIC")

    ccmp_header, rest = body[:CCMP_HEADER_SIZE], body[CCMP_HEADER_SIZE:]
    ciphertext, mic = rest[:-MIC_SIZE], rest[-MIC_SIZE:]
    pn = _ccmp_header_to_pn(ccmp_header)

    cipher = AES.new(key, AES.MODE_CCM, nonce=_nonce(header.addr2, pn), mac_len=MIC_SIZE)
    cipher.update(_aad(header))
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(mic)
    except ValueError as e:
        raise CcmpError(f"CCMP MIC verification failed: {e}") from e

    return DecryptedDataFrame(plaintext=plaintext, pn=pn, src=header.addr2, dest=header.addr1)


def build_data_frame(
    *,
    dest: bytes,
    src: bytes,
    bssid: bytes,
    seq_ctrl: int,
    pn: int,
    key: bytes,
    plaintext: bytes,
) -> bytes:
    """Build a protected 802.11 Data frame (no radiotap header) carrying
    `plaintext` (an SPTCP packet, typically) CCMP-encrypted with `key`/`pn`.

    `bssid` (addr3) is the "host" identity in the sense of crypto.py's
    build_hash_block() -- observed live to be whichever side answered the
    original broadcast Probe Request.
    """
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_DATA_PROTECTED,
        duration=0,  # not pinned down by any real capture yet, matches build_probe_response()'s stance
        addr1=dest,
        addr2=src,
        addr3=bssid,
        seq_ctrl=seq_ctrl,
    )
    cipher = AES.new(key, AES.MODE_CCM, nonce=_nonce(src, pn), mac_len=MIC_SIZE)
    cipher.update(_aad(header))
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)

    return dot11.build_management_header(header) + _pn_to_ccmp_header(pn) + ciphertext + mic
