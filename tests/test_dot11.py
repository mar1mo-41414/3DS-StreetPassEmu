import pytest

from streetpass_emu.dot11 import (
    ACTION_FRAME_CATEGORY,
    BROADCAST_MAC,
    FC_ACTION,
    FC_PROBE_REQUEST,
    FC_PROBE_RESPONSE,
    NINTENDO_OUI,
    SSID_IE_TAG,
    STREETPASS_SSID,
    ManagementFrameHeader,
    NintendoTag,
    build_action_frame,
    build_ies,
    build_management_header,
    build_nintendo_tag,
    build_probe_request,
    build_probe_response,
    build_vendor_specific_ie,
    extract_addr2,
    find_ie,
    parse_action_frame,
    parse_ies,
    parse_management_header,
    parse_nintendo_tag,
    parse_probe_request,
    parse_probe_response,
    parse_vendor_specific_ie,
    radiotap_header_length,
)

# Real StreetPass Probe Request capture from project findings
# (originally published on https://www.3dbrew.org/wiki/StreetPass), transcribed
# one hex-dump row at a time to avoid transcription errors.
_CAPTURE_ROWS = [
    "00 00 1a 00 2f 48 00 00 19 7d 19 de 2a 00 00 00",
    "12 16 9e 09 a0 00 c9 02 00 00 40 00 00 00 ff ff",
    "ff ff ff ff da 6b f7 22 f3 77 ff ff ff ff ff ff",
    "40 77 00 20 4e 69 6e 74 65 6e 64 6f 5f 33 44 53",
    "5f 63 6f 6e 74 69 6e 75 6f 75 73 5f 73 63 61 6e",
    "5f 30 30 30 01 08 82 84 8b 0c 12 96 18 24 32 04",
    "30 48 60 6c dd 15 00 1f 32 01 11 05 00 02 08 00",
    "00 f0 08 c8 34 6e 05 0f c9 c6 80 5b 6f bc 5a",
]
CAPTURED_FRAME = bytes.fromhex("".join(_CAPTURE_ROWS))


def test_captured_frame_is_the_expected_length():
    # Sanity check that the row-by-row transcription above reproduces the
    # 3dbrew capture byte-for-byte (radiotap 26B + 802.11 frame incl. FCS).
    assert len(CAPTURED_FRAME) == 16 * 7 + 15


def test_radiotap_header_length_matches_capture():
    assert radiotap_header_length(CAPTURED_FRAME) == 26


def test_extract_addr2_is_the_streetpass_mac():
    dot11_frame = CAPTURED_FRAME[radiotap_header_length(CAPTURED_FRAME):]
    assert extract_addr2(dot11_frame) == bytes.fromhex("da6bf722f377")


def test_ssid_is_present_in_the_capture():
    assert STREETPASS_SSID.encode("ascii") in CAPTURED_FRAME


CAPTURED_VENDOR_IE = bytes.fromhex("dd15001f320111050002080000f008c8346e050fc9c680")


def test_parse_vendor_specific_ie_from_capture():
    nintendo_tag_bytes = parse_vendor_specific_ie(CAPTURED_VENDOR_IE)
    assert nintendo_tag_bytes == bytes.fromhex("11050002080000f008c8346e050fc9c680")


def test_parse_vendor_specific_ie_rejects_wrong_oui():
    not_nintendo = b"\xdd\x06\x00\x11\x22\x01\xaa\xbb"
    with pytest.raises(ValueError):
        parse_vendor_specific_ie(not_nintendo)


def test_parse_nintendo_tag_from_capture():
    tag_bytes = bytes.fromhex("11050002080000f008c8346e050fc9c680")
    tag = parse_nintendo_tag(tag_bytes)

    assert tag.services == [bytes.fromhex("0002080000")]
    assert tag.console_id == bytes.fromhex("c8346e050fc9c680")


def test_build_nintendo_tag_round_trips_the_capture():
    expected = bytes.fromhex("11050002080000f008c8346e050fc9c680")
    tag = NintendoTag(services=[bytes.fromhex("0002080000")], console_id=bytes.fromhex("c8346e050fc9c680"))

    assert build_nintendo_tag(tag.services, tag.console_id) == expected


def test_build_vendor_specific_ie_round_trips_the_capture():
    nintendo_tag_bytes = bytes.fromhex("11050002080000f008c8346e050fc9c680")
    assert parse_vendor_specific_ie(build_vendor_specific_ie(nintendo_tag_bytes)) == nintendo_tag_bytes
    assert build_vendor_specific_ie(nintendo_tag_bytes)[2:5] == NINTENDO_OUI


def test_parse_nintendo_tag_rejects_bad_service_tag():
    with pytest.raises(ValueError):
        parse_nintendo_tag(bytes.fromhex("00050002080000f008c8346e050fc9c680"))


def test_parse_nintendo_tag_from_capture_with_multiple_services():
    # project findings (2026-09-17): a real third console (multiple
    # StreetPass-enabled titles played) had a Service Length of 46 -- not a
    # multiple of SERVICE_ENTRY_SIZE(5) -- because of an extra leading byte
    # right after the length field, ahead of the 9 real 5-byte entries. This
    # used to raise ValueError, which made find_nintendo_tag() return None
    # and silently drop this real console's broadcast probe entirely.
    tag_bytes = bytes.fromhex(
        "112e000d2900300002050032ffffffffffff000a790030000b47003000125d00"
        "3000135c003000020800000010980030f0080123456789abcdef"
    )
    tag = parse_nintendo_tag(tag_bytes)

    assert tag.console_id == bytes.fromhex("0123456789abcdef")
    assert len(tag.services) == 9
    assert bytes.fromhex("0002080000") in tag.services  # Mii Plaza, byte-identical to the single-service case


def test_build_nintendo_tag_rejects_wrong_console_id_size():
    with pytest.raises(ValueError):
        build_nintendo_tag([bytes.fromhex("0002080000")], bytes(7))


def test_build_nintendo_tag_rejects_wrong_service_size():
    with pytest.raises(ValueError):
        build_nintendo_tag([bytes(4)], bytes(8))


# ---- Generic IE walker ------------------------------------------------


def test_parse_ies_splits_the_capture_into_ssid_rates_and_vendor():
    dot11_frame = CAPTURED_FRAME[radiotap_header_length(CAPTURED_FRAME):]
    ies = parse_ies(dot11_frame[24:-4])  # strip mgmt header and FCS

    tags = [tag for tag, _ in ies]
    assert tags == [0x00, 0x01, 0x32, 0xDD]
    assert find_ie(ies, SSID_IE_TAG) == STREETPASS_SSID.encode("ascii")
    assert find_ie(ies, 0xDD) == CAPTURED_VENDOR_IE[2:]


def test_build_ies_round_trips_parse_ies():
    ies = [(0x00, b"hello"), (0xDD, bytes.fromhex("001f3201"))]
    assert parse_ies(build_ies(ies)) == ies


def test_find_ie_raises_when_missing():
    with pytest.raises(ValueError):
        find_ie([(0x00, b"x")], 0xDD)


def test_parse_ies_rejects_truncated_ie():
    with pytest.raises(ValueError):
        parse_ies(bytes([0x00, 0x05, 0x01, 0x02]))  # says 5 bytes, only has 2


# ---- Management frame header ------------------------------------------


def test_parse_management_header_from_capture():
    dot11_frame = CAPTURED_FRAME[radiotap_header_length(CAPTURED_FRAME):]
    header = parse_management_header(dot11_frame)

    assert header.frame_control == FC_PROBE_REQUEST
    assert header.addr1 == bytes.fromhex("ffffffffffff")
    assert header.addr2 == bytes.fromhex("da6bf722f377")
    assert header.addr3 == bytes.fromhex("ffffffffffff")


def test_build_management_header_round_trips():
    header = ManagementFrameHeader(
        frame_control=FC_PROBE_REQUEST,
        duration=0,
        addr1=bytes.fromhex("ffffffffffff"),
        addr2=bytes.fromhex("da6bf722f377"),
        addr3=bytes.fromhex("ffffffffffff"),
        seq_ctrl=0x7740,
    )
    assert parse_management_header(build_management_header(header)) == header


def test_build_management_header_rejects_wrong_address_size():
    header = ManagementFrameHeader(
        frame_control=FC_PROBE_REQUEST,
        duration=0,
        addr1=bytes(5),
        addr2=bytes(6),
        addr3=bytes(6),
        seq_ctrl=0,
    )
    with pytest.raises(ValueError):
        build_management_header(header)


# ---- Probe Request / Probe Response ------------------------------------


def test_parse_probe_request_from_capture():
    dot11_frame = CAPTURED_FRAME[radiotap_header_length(CAPTURED_FRAME):-4]  # strip FCS
    probe = parse_probe_request(dot11_frame)

    assert probe.header.frame_control == FC_PROBE_REQUEST
    assert probe.ssid == STREETPASS_SSID.encode("ascii")
    assert find_ie(probe.ies, 0xDD) == CAPTURED_VENDOR_IE[2:]


def test_parse_probe_request_rejects_wrong_frame_control():
    not_a_request = bytes(24)  # frame_control == 0
    with pytest.raises(ValueError):
        parse_probe_request(not_a_request)


def test_build_probe_response_round_trips_via_parse_probe_response():
    header = ManagementFrameHeader(
        frame_control=FC_PROBE_REQUEST,  # the *request's* header; build_probe_response fixes the FC
        duration=0,
        addr1=bytes.fromhex("da6bf722f377"),  # replying to the requester
        addr2=bytes.fromhex("112233445566"),  # our own StreetPass MAC
        addr3=bytes.fromhex("112233445566"),
        seq_ctrl=0,
    )
    nintendo_tag = build_nintendo_tag([bytes.fromhex("0002080000")], bytes.fromhex("aabbccddeeff0011"))
    ies = [
        (SSID_IE_TAG, STREETPASS_SSID.encode("ascii")),
        (0xDD, NINTENDO_OUI + bytes([0x01]) + nintendo_tag),
    ]

    frame = build_probe_response(header=header, ies=ies)
    response = parse_probe_response(frame)

    assert response.header.frame_control == FC_PROBE_RESPONSE
    assert response.header.addr1 == header.addr1
    assert response.header.addr2 == header.addr2
    assert response.ssid == STREETPASS_SSID.encode("ascii")
    assert parse_nintendo_tag(find_ie(response.ies, 0xDD)[4:]).console_id == bytes.fromhex("aabbccddeeff0011")


def test_parse_probe_response_rejects_wrong_frame_control():
    not_a_response = bytes(36)  # frame_control == 0
    with pytest.raises(ValueError):
        parse_probe_response(not_a_response)


def test_build_probe_request_round_trips_via_parse_probe_request_broadcast():
    nintendo_tag = build_nintendo_tag([bytes.fromhex("0002080000")], bytes.fromhex("aabbccddeeff0011"))
    ies = [(0xDD, NINTENDO_OUI + bytes([0x01]) + nintendo_tag)]

    frame = build_probe_request(addr2=bytes.fromhex("112233445566"), ies=ies)
    request = parse_probe_request(frame)

    assert request.header.frame_control == FC_PROBE_REQUEST
    assert request.header.addr1 == BROADCAST_MAC
    assert request.header.addr2 == bytes.fromhex("112233445566")
    assert request.ssid == STREETPASS_SSID.encode("ascii")
    assert parse_nintendo_tag(find_ie(request.ies, 0xDD)[4:]).console_id == bytes.fromhex("aabbccddeeff0011")


def test_build_probe_request_unicast_second_request_has_no_ssid_or_tag():
    """project findings: a real console's second (unicast) Probe
    Request carries an *empty* SSID IE and no Nintendo tag at all."""
    frame = build_probe_request(
        addr2=bytes.fromhex("112233445566"),
        addr1=bytes.fromhex("da6bf722f377"),
        ssid=b"",
        ies=None,
    )
    request = parse_probe_request(frame)

    assert request.header.addr1 == bytes.fromhex("da6bf722f377")
    assert request.ssid == b""
    assert len(request.ies) == 1  # just the empty SSID IE, no Nintendo tag


def test_build_action_frame_round_trips_via_parse_action_frame():
    frame = build_action_frame(
        addr1=bytes.fromhex("da6bf722f377"),
        addr2=bytes.fromhex("112233445566"),
    )
    action = parse_action_frame(frame)

    assert action.header.frame_control == FC_ACTION
    assert action.header.addr1 == bytes.fromhex("da6bf722f377")
    assert action.header.addr2 == bytes.fromhex("112233445566")
    assert action.payload == b"\x00\x00"  # only value ever captured live so far


def test_parse_action_frame_from_capture():
    """project findings's real capture: fc=0x00d0, then
    Category=0x7f, OUI=00:1f:32, then two 0x00 bytes."""
    header = bytes.fromhex("d000d500") + bytes(6) + bytes.fromhex("112233445566") + bytes(6) + bytes(2)
    body = bytes([ACTION_FRAME_CATEGORY]) + NINTENDO_OUI + bytes(2)
    action = parse_action_frame(header + body)

    assert action.header.frame_control == FC_ACTION
    assert action.payload == bytes(2)


def test_parse_action_frame_rejects_wrong_frame_control():
    not_an_action = bytes(24) + bytes([ACTION_FRAME_CATEGORY]) + NINTENDO_OUI + bytes(2)
    with pytest.raises(ValueError):
        parse_action_frame(not_an_action)


def test_parse_action_frame_rejects_non_nintendo_oui():
    header = ManagementFrameHeader(
        frame_control=FC_ACTION, duration=0,
        addr1=bytes(6), addr2=bytes(6), addr3=bytes(6), seq_ctrl=0,
    )
    frame = build_management_header(header) + bytes([ACTION_FRAME_CATEGORY]) + bytes.fromhex("000000") + bytes(2)
    with pytest.raises(ValueError):
        parse_action_frame(frame)
