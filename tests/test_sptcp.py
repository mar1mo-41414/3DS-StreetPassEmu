import pytest

from streetpass_emu.sptcp import (
    DEFAULT_BUFFER_SIZE,
    FLAG_ACK,
    FLAG_SYN,
    SptcpHeader,
    build_handshake_packet,
    build_header,
    parse_header,
)

# Real 3-way handshake capture, project findings (from 3dbrew's SPTCP
# page). A=initiator, B=peer.
A_SYN = bytes.fromhex("5959" "3000" "addeafbe" "00000000" "00000000" "0c" "02" "b838" "00000000")
B_SYN_ACK = bytes.fromhex("5959" "3000" "addeafbe" "00000000" "00000000" "0c" "12" "b838" "00000000")
A_ACK = bytes.fromhex("5959" "3000" "addeafbe" "00000000" "00000000" "0c" "10" "b838" "00000000")


def test_capture_packets_are_24_bytes():
    assert len(A_SYN) == len(B_SYN_ACK) == len(A_ACK) == 0x18


def test_parse_header_from_real_syn_packet():
    header = parse_header(A_SYN)
    assert header.total_size == 0x30
    assert header.bytes_sent == 0
    assert header.bytes_received == 0
    assert header.flags == FLAG_SYN
    assert header.max_buffer_size == DEFAULT_BUFFER_SIZE


def test_parse_header_from_real_syn_ack_packet():
    header = parse_header(B_SYN_ACK)
    assert header.flags == FLAG_SYN | FLAG_ACK


def test_parse_header_from_real_ack_packet():
    header = parse_header(A_ACK)
    assert header.flags == FLAG_ACK


def test_build_handshake_packet_matches_the_real_syn_capture():
    assert build_handshake_packet(FLAG_SYN) == A_SYN


def test_build_handshake_packet_matches_the_real_syn_ack_capture():
    assert build_handshake_packet(FLAG_SYN | FLAG_ACK) == B_SYN_ACK


def test_build_handshake_packet_matches_the_real_ack_capture():
    assert build_handshake_packet(FLAG_ACK) == A_ACK


def test_build_header_round_trips_parse_header():
    header = SptcpHeader(total_size=0x30 + 100, bytes_sent=50, bytes_received=10, flags=FLAG_ACK)
    assert parse_header(build_header(header)) == header


def test_parse_header_rejects_bad_magic():
    corrupted = bytes([0x00, 0x00]) + A_SYN[2:]
    with pytest.raises(ValueError):
        parse_header(corrupted)


def test_parse_header_rejects_bad_constant():
    corrupted = A_SYN[:4] + bytes(4) + A_SYN[8:]
    with pytest.raises(ValueError):
        parse_header(corrupted)


def test_parse_header_rejects_nonzero_padding():
    corrupted = A_SYN[:20] + bytes([0xFF, 0, 0, 0])
    with pytest.raises(ValueError):
        parse_header(corrupted)


def test_parse_header_rejects_truncated_data():
    with pytest.raises(ValueError):
        parse_header(A_SYN[:10])
