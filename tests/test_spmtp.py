import pytest

from streetpass_emu.spmtp import (
    HANDSHAKE_MESSAGE_ORDER,
    FriendCodePacket,
    FriendFlagPacket,
    HandshakeHeader,
    IdentityPacket,
    MessageBoxMetadataEntry,
    PacketType,
    TmpBoxHeader,
    TmpBoxMetadataEntry,
    build_friend_code_packet,
    build_friend_flag_packet,
    build_handshake_header,
    build_identity_accept_packet,
    build_identity_packet,
    build_message_box_metadata_list,
    build_tmp_box_header,
    build_tmp_box_metadata_list,
    parse_friend_code_packet,
    parse_friend_flag_packet,
    parse_handshake_header,
    parse_identity_packet,
    parse_message_box_metadata_list,
    parse_tmp_box_header,
    parse_tmp_box_metadata_list,
)
from streetpass_emu.spmtp import friend_code_value_from_string, principal_id_checksum


def test_handshake_message_order_alternates_client_and_master_pairs():
    assert HANDSHAKE_MESSAGE_ORDER == (
        0x41, 0x42, 0x43, 0x43,
        0x11, 0x12, 0x21, 0x22, 0x23, 0x24,
        0x31, 0x32, 0x33, 0x34,
        0x81, 0x81,
    )


def test_handshake_header_round_trips():
    header = HandshakeHeader(packet_type=PacketType.IDENTITY_CLIENT, content_size=0x28)
    assert parse_handshake_header(build_handshake_header(header)) == header


def test_handshake_header_rejects_bad_magic():
    with pytest.raises(ValueError):
        parse_handshake_header(bytes(16))


def test_identity_packet_round_trips():
    packet = IdentityPacket(
        transferable_id=bytes.fromhex("0011223344556677"),
        session_id=0xDEADBEEF,
        original_mac=bytes.fromhex("aabbccddeeff"),
        timestamp=bytes.fromhex("000102030405060708090a0b"),
    )
    built = build_identity_packet(packet)
    assert len(built) == IdentityPacket.SIZE
    assert parse_identity_packet(built) == packet


def test_identity_packet_rejects_wrong_field_sizes():
    with pytest.raises(ValueError):
        IdentityPacket(transferable_id=bytes(7), session_id=0, original_mac=bytes(6), timestamp=bytes(12))
    with pytest.raises(ValueError):
        IdentityPacket(transferable_id=bytes(8), session_id=0, original_mac=bytes(5), timestamp=bytes(12))
    with pytest.raises(ValueError):
        IdentityPacket(transferable_id=bytes(8), session_id=0, original_mac=bytes(6), timestamp=bytes(11))


def test_identity_accept_packet_is_0x10_bytes():
    assert len(build_identity_accept_packet()) == 0x10


def test_friend_code_packet_round_trips():
    packet = FriendCodePacket(friend_code=0x1122334455667788)
    assert parse_friend_code_packet(build_friend_code_packet(packet)) == packet


def test_friend_flag_packet_round_trips():
    packet = FriendFlagPacket(flag=1)
    assert parse_friend_flag_packet(build_friend_flag_packet(packet)) == packet


def test_message_box_metadata_list_round_trips():
    entries = [
        MessageBoxMetadataEntry(title_id=0x00020800, send_mode=3, flag=0, send_state=0, send_size=1000, message_count=2),
        MessageBoxMetadataEntry(title_id=0x00030500, send_mode=0, flag=1, send_state=5, send_size=200, message_count=1),
    ]
    built = build_message_box_metadata_list(entries)
    assert parse_message_box_metadata_list(built) == entries


def test_message_box_metadata_list_rejects_bad_magic():
    with pytest.raises(ValueError):
        parse_message_box_metadata_list(bytes(0x2C))


def test_tmp_box_metadata_list_round_trips():
    entries = [
        TmpBoxMetadataEntry(title_id=0x00020800, size=1234),
        TmpBoxMetadataEntry(title_id=0x00030500, size=5678),
    ]
    built = build_tmp_box_metadata_list(entries)
    assert parse_tmp_box_metadata_list(built) == entries


def test_tmp_box_metadata_list_pads_a_non_empty_list_to_the_real_fixed_size():
    """project findings: a live capture of a real peer's own non-empty
    0x81 was a fixed 196 bytes (4 + 24*8) with 23 trailing all-zero padding
    entries after the one real entry, not just the 12 bytes our own
    unpadded builder used to produce -- suspected to be why a peer got
    stuck endlessly retransmitting its own send after reading our
    too-short reply."""
    entry = TmpBoxMetadataEntry(title_id=0x00020800, size=32712)
    built = build_tmp_box_metadata_list([entry])
    assert len(built) == 0xC4
    assert built == (
        bytes.fromhex("0100000000080200c87f0000") + bytes(23 * TmpBoxMetadataEntry.SIZE)
    )
    assert parse_tmp_box_metadata_list(built) == [entry]


def test_tmp_box_metadata_list_stays_unpadded_when_empty():
    """The empty case isn't touched by the §7.37
    padding fix -- only known to matter once we're actually offering
    something, and changing a path that's already worked live risks a
    regression for no benefit."""
    assert build_tmp_box_metadata_list([]) == bytes(4)


def test_tmp_box_header_round_trips():
    header = TmpBoxHeader(size=100, title_id=0x00020800, group_id=1, message_count=3)
    assert parse_tmp_box_header(build_tmp_box_header(header)) == header


def test_tmp_box_header_rejects_bad_magic():
    with pytest.raises(ValueError):
        parse_tmp_box_header(bytes(0x14))


def test_friend_code_value_from_string_matches_a_known_valid_code():
    """4126-2228-0312 is a checksum-valid (synthetic) friend code:
    principal_id = 412622280312 & 0xffffffff = 305419896, and
    SHA-1(305419896 as 4 bytes LE)[0] >> 1 equals 412622280312 >> 32 = 96."""
    value = friend_code_value_from_string("4126-2228-0312")

    assert value == 412622280312
    assert value & 0xFFFFFFFF == 305419896
    assert principal_id_checksum(305419896) == 96
    assert value >> 32 == 96


def test_friend_code_value_from_string_accepts_no_dashes():
    assert friend_code_value_from_string("412622280312") == friend_code_value_from_string("4126-2228-0312")


def test_friend_code_value_from_string_rejects_bad_checksum():
    with pytest.raises(ValueError):
        friend_code_value_from_string("1234-5678-9012")


def test_friend_code_value_from_string_rejects_wrong_length():
    with pytest.raises(ValueError):
        friend_code_value_from_string("1234-5678")
