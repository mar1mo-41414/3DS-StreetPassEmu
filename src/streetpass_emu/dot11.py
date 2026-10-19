"""802.11 frame bits specific to StreetPass: the Nintendo vendor IE and framing
constants ( the annotated capture this is built
from).

Scope is deliberately narrow: this module only knows about the pieces needed
to recognize/build a StreetPass Probe Request's Nintendo tag. General 802.11
frame construction (radiotap, full management-frame headers) belongs to
whatever monitor-mode driver layer ends up wrapping this (see
docs/MONITOR_MODE.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

STREETPASS_SSID = "Nintendo_3DS_continuous_scan_000"
BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"

SUPPORTED_RATES_IE_TAG = 0x01
EXTENDED_SUPPORTED_RATES_IE_TAG = 0x32

# The exact Supported Rates / Extended Supported Rates IE bodies seen in the
# real capture -- included as defaults when building
# our own frames since a real 3DS's own frames always carry them, and reduced
# risk of a receiver validating fewer fields than a genuine StreetPass frame.
CAPTURED_SUPPORTED_RATES = bytes.fromhex("82848b0c12961824")
CAPTURED_EXTENDED_SUPPORTED_RATES = bytes.fromhex("3048606c")

MGMT_HEADER_SIZE = 24
FC_PROBE_REQUEST = 0x0040
FC_PROBE_RESPONSE = 0x0050
# Management, subtype 13 (Action) -- confirmed live (project findings
# §7.6.3's real capture: "fc=0x00d0, type=0/Management, subtype=13/Action").
FC_ACTION = 0x00D0
SSID_IE_TAG = 0x00

# frame_control (as parsed by parse_management_header: little-endian uint16
# of the two FC octets) Type field and Protected flag. A real StreetPass
# CCMP Data frame observed live has frame_control=0x4008: Type=Data (2),
# non-QoS subtype 0, ToDS=FromDS=0 (so it uses the same 3-address, no-QoS-
# Control 24-byte header as a management frame), Protected bit set
#.
FRAME_TYPE_DATA = 0x2
_FRAME_TYPE_SHIFT = 2
_FRAME_TYPE_MASK = 0x3
PROTECTED_FLAG = 0x4000

# The exact frame_control real StreetPass CCMP Data frames use, both
# directions: non-QoS Data, ToDS=FromDS=0,
# Protected set, everything else clear.
FC_DATA_PROTECTED = 0x4008


def frame_type(frame_control: int) -> int:
    """The 2-bit 802.11 Type field (0=Management, 1=Control, 2=Data)."""
    return (frame_control >> _FRAME_TYPE_SHIFT) & _FRAME_TYPE_MASK


def is_protected(frame_control: int) -> bool:
    """Whether the frame's Protected (WEP/CCMP) bit is set."""
    return bool(frame_control & PROTECTED_FLAG)

# Probe Response carries 12 bytes of fixed fields (timestamp, beacon interval,
# capability info) between the header and the first IE; Probe Request has none.
PROBE_RESPONSE_FIXED_FIELDS_SIZE = 12

NINTENDO_OUI = bytes.fromhex("001f32")
NINTENDO_OUI_TYPE = 0x01

VENDOR_SPECIFIC_IE_TAG = 0xDD
ACTION_FRAME_CATEGORY = 0x7F

SERVICE_TAG = 0x11
SERVICE_ENTRY_SIZE = 5
CONSOLE_ID_TAG = 0xF0
CONSOLE_ID_SIZE = 8

# StreetPass Probe Requests increment their sequence number by 3 (not 1) while
# actively scanning, until a Probe Response arrives.
SCANNING_SEQUENCE_STEP = 3


@dataclass(frozen=True)
class NintendoTag:
    """The StreetPass-specific payload of the Nintendo vendor IE."""

    services: List[bytes]
    console_id: bytes


def radiotap_header_length(data: bytes) -> int:
    """Return the length of the leading radiotap header in ``data`` (bytes 2-3,
    little-endian), so callers can skip straight to the 802.11 frame."""
    if len(data) < 4:
        raise ValueError(f"data must be at least 4 bytes, got {len(data)}")
    return int.from_bytes(data[2:4], "little")


def extract_addr2(dot11_frame: bytes) -> bytes:
    """Addr2 (transmitter address) of an 802.11 frame, starting right after
    any radiotap header. This is the sender's StreetPass MAC on a Probe
    Request/Response (project findings, §2.3.1)."""
    if len(dot11_frame) < 16:
        raise ValueError(f"dot11_frame must be at least 16 bytes, got {len(dot11_frame)}")
    return bytes(dot11_frame[10:16])


def parse_vendor_specific_ie(ie: bytes) -> bytes:
    """Given a full Vendor Specific IE (tag 0xDD), verify it is Nintendo's and
    return the Nintendo tag bytes that follow the OUI + OUI type."""
    if len(ie) < 6 or ie[0] != VENDOR_SPECIFIC_IE_TAG:
        raise ValueError("not a Vendor Specific IE (expected tag 0xDD)")
    length = ie[1]
    if len(ie) != 2 + length:
        raise ValueError(f"IE length field says {length}, but got {len(ie) - 2} bytes of body")
    oui, oui_type, body = ie[2:5], ie[5], ie[6:]
    if oui != NINTENDO_OUI or oui_type != NINTENDO_OUI_TYPE:
        raise ValueError(f"not Nintendo's vendor IE (OUI={oui.hex()}, type={oui_type:#x})")
    return body


def parse_nintendo_tag(tag: bytes) -> NintendoTag:
    """Parse the Nintendo tag body (as returned by parse_vendor_specific_ie)
    into its StreetPass Services list and consoleID.
    """
    if len(tag) < 2 or tag[0] != SERVICE_TAG:
        raise ValueError(f"expected StreetPass Service Tag {SERVICE_TAG:#x} at offset 0")
    services_length = tag[1]

    # project findings (2026-09-17): this project's own captures (console A/
    # console B) only ever advertised a single service (Mii Plaza), where
    # services_length is a clean multiple of SERVICE_ENTRY_SIZE and the entries
    # start immediately. A real continuous-scan broadcast probe from a third
    # console (multiple StreetPass-enabled titles recently played) instead had
    # services_length one byte too many for that -- a real capture decoded
    # cleanly into N well-formed 5-byte entries (one of them byte-identical to
    # the known Mii Plaza service ID) only once a single leading byte right
    # after the length field was skipped first. That leading byte's own
    # meaning (a count? padding?) is still unconfirmed, so it's just dropped
    # here rather than exposed -- but treating it as a hard parse failure
    # (the strict multiple-of-5 check below) made find_nintendo_tag() return
    # None for an otherwise perfectly genuine Nintendo tag, which in turn made
    # _handle_probe_request() silently ignore that real console's broadcast
    # probe entirely (project findings investigation, session.py).
    entry_pad = 0
    if services_length % SERVICE_ENTRY_SIZE != 0:
        if (services_length - 1) % SERVICE_ENTRY_SIZE == 0 and services_length >= 1:
            entry_pad = 1
        else:
            raise ValueError(f"StreetPass Service Length {services_length} is not a multiple of {SERVICE_ENTRY_SIZE}"
                              f" (nor that plus 1)")

    services_start = 2
    services_end = services_start + services_length
    console_id_tag_offset = -(CONSOLE_ID_SIZE + 2)
    console_id_length_offset = -(CONSOLE_ID_SIZE + 1)

    if services_end != len(tag) + console_id_tag_offset:
        raise ValueError("StreetPass Services field does not end where the consoleID tag begins")
    if tag[console_id_tag_offset] != CONSOLE_ID_TAG:
        raise ValueError(f"expected StreetPass consoleID Tag {CONSOLE_ID_TAG:#x}")
    if tag[console_id_length_offset] != CONSOLE_ID_SIZE:
        raise ValueError(f"expected StreetPass consoleID Length {CONSOLE_ID_SIZE:#x}")

    raw_services = tag[services_start + entry_pad:services_end]
    services = [raw_services[i:i + SERVICE_ENTRY_SIZE] for i in range(0, len(raw_services), SERVICE_ENTRY_SIZE)]
    console_id = tag[-CONSOLE_ID_SIZE:]
    return NintendoTag(services=services, console_id=bytes(console_id))


def build_nintendo_tag(services: List[bytes], console_id: bytes) -> bytes:
    """Inverse of parse_nintendo_tag: assemble the Nintendo tag body."""
    if len(console_id) != CONSOLE_ID_SIZE:
        raise ValueError(f"console_id must be {CONSOLE_ID_SIZE} bytes, got {len(console_id)}")
    for service in services:
        if len(service) != SERVICE_ENTRY_SIZE:
            raise ValueError(f"each service must be {SERVICE_ENTRY_SIZE} bytes, got {len(service)}")

    raw_services = b"".join(services)
    return bytes([SERVICE_TAG, len(raw_services)]) + raw_services + bytes([CONSOLE_ID_TAG, CONSOLE_ID_SIZE]) + console_id


def build_vendor_specific_ie(nintendo_tag: bytes) -> bytes:
    """Wrap a Nintendo tag body back into a full Vendor Specific IE."""
    body = NINTENDO_OUI + bytes([NINTENDO_OUI_TYPE]) + nintendo_tag
    return bytes([VENDOR_SPECIFIC_IE_TAG, len(body)]) + body


def find_nintendo_tag(ies: List[Tuple[int, bytes]]) -> Optional[NintendoTag]:
    """Scan a parsed IE list for Nintendo's vendor IE and parse its
    StreetPass tag, or None if there isn't a well-formed one."""
    for tag, body in ies:
        if tag == VENDOR_SPECIFIC_IE_TAG and body[:3] == NINTENDO_OUI and body[3:4] == bytes([NINTENDO_OUI_TYPE]):
            try:
                return parse_nintendo_tag(body[4:])
            except ValueError:
                return None
    return None


# ---- Generic 802.11 management-frame plumbing -----------------------------
#
# Everything below is generic 802.11 (not StreetPass-specific): a plain
# tag/length/value IE walker and the 24-byte management-frame header shared
# by Probe Request and Probe Response. Verified against the real capture in
# project findings (see tests/test_dot11.py).


def parse_ies(data: bytes) -> List[Tuple[int, bytes]]:
    """Walk a run of tag/length/value Information Elements."""
    ies: List[Tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError(f"truncated IE header at offset {offset}")
        tag = data[offset]
        length = data[offset + 1]
        body = data[offset + 2:offset + 2 + length]
        if len(body) != length:
            raise ValueError(f"IE tag {tag:#x} at offset {offset} says length {length}, only {len(body)} bytes follow")
        ies.append((tag, bytes(body)))
        offset += 2 + length
    return ies


def build_ies(ies: List[Tuple[int, bytes]]) -> bytes:
    """Inverse of parse_ies()."""
    out = bytearray()
    for tag, body in ies:
        out += bytes([tag, len(body)]) + body
    return bytes(out)


def find_ie(ies: List[Tuple[int, bytes]], tag: int) -> bytes:
    """The body of the first IE matching ``tag``, or raises if none does."""
    for ie_tag, body in ies:
        if ie_tag == tag:
            return body
    raise ValueError(f"no IE with tag {tag:#x}")


@dataclass(frozen=True)
class ManagementFrameHeader:
    """The 24-byte header shared by every 802.11 management frame."""

    frame_control: int
    duration: int
    addr1: bytes  # RA/DA
    addr2: bytes  # TA/SA -- the StreetPass MAC on Probe Request/Response
    addr3: bytes  # BSSID
    seq_ctrl: int


def parse_management_header(dot11_frame: bytes) -> ManagementFrameHeader:
    if len(dot11_frame) < MGMT_HEADER_SIZE:
        raise ValueError(f"dot11_frame must be at least {MGMT_HEADER_SIZE} bytes, got {len(dot11_frame)}")
    return ManagementFrameHeader(
        frame_control=int.from_bytes(dot11_frame[0:2], "little"),
        duration=int.from_bytes(dot11_frame[2:4], "little"),
        addr1=bytes(dot11_frame[4:10]),
        addr2=bytes(dot11_frame[10:16]),
        addr3=bytes(dot11_frame[16:22]),
        seq_ctrl=int.from_bytes(dot11_frame[22:24], "little"),
    )


def build_management_header(header: ManagementFrameHeader) -> bytes:
    for name, value in (("addr1", header.addr1), ("addr2", header.addr2), ("addr3", header.addr3)):
        if len(value) != 6:
            raise ValueError(f"{name} must be 6 bytes, got {len(value)}")
    return (
        header.frame_control.to_bytes(2, "little")
        + header.duration.to_bytes(2, "little")
        + header.addr1 + header.addr2 + header.addr3
        + header.seq_ctrl.to_bytes(2, "little")
    )


@dataclass(frozen=True)
class ProbeRequest:
    header: ManagementFrameHeader
    ssid: bytes
    ies: List[Tuple[int, bytes]]  # full IE list, including the SSID IE


def parse_probe_request(dot11_frame: bytes) -> ProbeRequest:
    header = parse_management_header(dot11_frame)
    if header.frame_control != FC_PROBE_REQUEST:
        raise ValueError(f"not a Probe Request (frame_control={header.frame_control:#06x})")
    ies = parse_ies(dot11_frame[MGMT_HEADER_SIZE:])
    ssid = find_ie(ies, SSID_IE_TAG)
    return ProbeRequest(header=header, ssid=ssid, ies=ies)


@dataclass(frozen=True)
class ProbeResponse:
    header: ManagementFrameHeader
    timestamp: int
    beacon_interval: int
    capability_info: int
    ssid: bytes
    ies: List[Tuple[int, bytes]]  # full IE list, including the SSID IE


def parse_probe_response(dot11_frame: bytes) -> ProbeResponse:
    header = parse_management_header(dot11_frame)
    if header.frame_control != FC_PROBE_RESPONSE:
        raise ValueError(f"not a Probe Response (frame_control={header.frame_control:#06x})")
    fixed_end = MGMT_HEADER_SIZE + PROBE_RESPONSE_FIXED_FIELDS_SIZE
    if len(dot11_frame) < fixed_end:
        raise ValueError("truncated Probe Response fixed fields")
    timestamp = int.from_bytes(dot11_frame[MGMT_HEADER_SIZE:MGMT_HEADER_SIZE + 8], "little")
    beacon_interval = int.from_bytes(dot11_frame[MGMT_HEADER_SIZE + 8:MGMT_HEADER_SIZE + 10], "little")
    capability_info = int.from_bytes(dot11_frame[MGMT_HEADER_SIZE + 10:fixed_end], "little")
    ies = parse_ies(dot11_frame[fixed_end:])
    ssid = find_ie(ies, SSID_IE_TAG)
    return ProbeResponse(
        header=header,
        timestamp=timestamp,
        beacon_interval=beacon_interval,
        capability_info=capability_info,
        ssid=ssid,
        ies=ies,
    )


def build_probe_request(
    *,
    addr2: bytes,
    addr1: bytes = BROADCAST_MAC,
    ssid: bytes = STREETPASS_SSID.encode("ascii"),
    ies: Optional[List[Tuple[int, bytes]]] = None,
    seq_ctrl: int = 0,
) -> bytes:
    """Build a raw Probe Request frame we send ourselves as the "prober"
    ( step 1 and step 3 -- this project has only
    ever answered a peer's Probe Request before, ``2026-09-15`` is the first
    time it initiates one itself).

    Broadcast (``addr1=BROADCAST_MAC``, the default) is step 1's continuous-
    scan probe -- ``ssid`` should be ``STREETPASS_SSID`` and ``ies`` should
    include our own Nintendo tag so a peer recognizes us as a StreetPass
    device (mirrors what a real console's own broadcast Probe Request
    carries). The follow-up unicast one (step 3, after the peer's Action
    frame) should instead pass the peer's own MAC as ``addr1``, an empty
    ``ssid``, and no Nintendo tag -- confirmed live to be how a real
    console's second Probe Request looks, even
    though this function only builds *our own* frames, not a peer's.
    """
    header = ManagementFrameHeader(
        frame_control=FC_PROBE_REQUEST,
        duration=0,
        addr1=addr1,
        addr2=addr2,
        addr3=addr1,
        seq_ctrl=seq_ctrl,
    )
    ssid_ie = (SSID_IE_TAG, ssid)
    body_ies = [ssid_ie] + (ies or [])
    return build_management_header(header) + build_ies(body_ies)


def build_action_frame(*, addr1: bytes, addr2: bytes, payload: bytes = b"\x00\x00", seq_ctrl: int = 0) -> bytes:
    """Build a raw StreetPass Action frame (category 0x7F, Nintendo OUI
    00:1f:32) -- the one 802.11 management frame this project has never
    sent. A real console's "prober" side sends
    exactly one of these, addressed to whichever peer just answered its
    first (broadcast) Probe Request, right before its second (unicast)
    Probe Request ('s captured sequence).

    ``payload`` is whatever follows the 6-byte header
    (Category+OUI+OUI-type... actually Category(1)+OUI(3)+2 more bytes per
    the one real capture on file) -- only ever
    observed as ``00 00`` once, so that's the default; the real meaning (a
    fixed value vs. something that must echo/respond to whatever the peer's
    own Action frame carried) is still unresolved
    and worth varying once a peer's own Action frame can be captured for
    comparison."""
    header = ManagementFrameHeader(
        frame_control=FC_ACTION,
        duration=0,
        addr1=addr1,
        addr2=addr2,
        addr3=addr2,
        seq_ctrl=seq_ctrl,
    )
    return build_management_header(header) + bytes([ACTION_FRAME_CATEGORY]) + NINTENDO_OUI + payload


@dataclass(frozen=True)
class ActionFrame:
    header: ManagementFrameHeader
    payload: bytes  # whatever follows Category+OUI


def parse_action_frame(dot11_frame: bytes) -> ActionFrame:
    """Parse a received StreetPass Action frame. Raises ValueError if this
    isn't an Action frame, or isn't Nintendo's (some other category/OUI)."""
    header = parse_management_header(dot11_frame)
    if header.frame_control != FC_ACTION:
        raise ValueError(f"not an Action frame (frame_control={header.frame_control:#06x})")
    body = dot11_frame[MGMT_HEADER_SIZE:]
    if len(body) < 4 or body[0] != ACTION_FRAME_CATEGORY or body[1:4] != NINTENDO_OUI:
        raise ValueError("not a StreetPass (Nintendo) Action frame")
    return ActionFrame(header=header, payload=bytes(body[4:]))


def build_probe_response(
    *,
    header: ManagementFrameHeader,
    ies: List[Tuple[int, bytes]],
    timestamp: int = 0,
    beacon_interval: int = 0,
    capability_info: int = 0,
) -> bytes:
    """Build a raw Probe Response frame (no radiotap header, no FCS -- see
    docs/MONITOR_MODE.md for how a Driver.inject_frame() call expects this).

    Field values beyond the header/IEs (timestamp, beacon_interval,
    capability_info) are not pinned down by any real capture yet -- zero is a reasonable placeholder, override
    once real StreetPass Probe Response captures are available to compare
    against (task 3).
    """
    response_header = ManagementFrameHeader(
        frame_control=FC_PROBE_RESPONSE,
        duration=header.duration,
        addr1=header.addr1,
        addr2=header.addr2,
        addr3=header.addr3,
        seq_ctrl=header.seq_ctrl,
    )
    return (
        build_management_header(response_header)
        + timestamp.to_bytes(8, "little")
        + beacon_interval.to_bytes(2, "little")
        + capability_info.to_bytes(2, "little")
        + build_ies(ies)
    )
