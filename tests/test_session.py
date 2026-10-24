from dataclasses import replace

from streetpass_emu import ccmp, crypto, dot11, spmtp, sptcp
from streetpass_emu import session as session_module
from streetpass_emu.session import (
    LOCALLY_ADMINISTERED_BIT,
    MULTICAST_BIT,
    PeerState,
    ProberStage,
    SessionIdentity,
    StreetPassResponder,
    generate_session_identity,
)

# Arbitrary, non-secret placeholder for keyslot 0x2E's normal key -- these
# tests only exercise the CCMP/SPTCP reply wiring, not any real device's key
#.
_TEST_KEYSLOT_2E_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

# Same real StreetPass Probe Request capture used in tests/test_dot11.py
#.
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
PEER_MAC = bytes.fromhex("da6bf722f377")
PEER_CONSOLE_ID = bytes.fromhex("c8346e050fc9c680")
PEER_SERVICE = bytes.fromhex("0002080000")


def _peer_broadcast_probe_request() -> bytes:
    """The real captured frame, radiotap header and FCS stripped."""
    return CAPTURED_FRAME[dot11.radiotap_header_length(CAPTURED_FRAME):-4]


def _build_probe_request(header: dot11.ManagementFrameHeader, ies) -> bytes:
    return dot11.build_management_header(header) + dot11.build_ies(ies)


def _responder() -> StreetPassResponder:
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    return StreetPassResponder(identity=identity, services=[PEER_SERVICE])


def test_generate_session_identity_has_locally_administered_unicast_mac():
    identity = generate_session_identity()
    assert len(identity.mac) == 6
    assert len(identity.console_id) == 8
    assert identity.mac[0] & LOCALLY_ADMINISTERED_BIT
    assert not (identity.mac[0] & MULTICAST_BIT)


def test_generate_session_identity_is_randomized():
    a = generate_session_identity()
    b = generate_session_identity()
    assert a != b


def test_responder_replies_to_a_real_broadcast_probe_request():
    responder = _responder()

    reply = responder.handle_frame(_peer_broadcast_probe_request())

    assert len(reply) == 1
    response = dot11.parse_probe_response(reply[0])
    assert response.header.addr1 == PEER_MAC
    assert response.header.addr2 == responder.identity.mac
    assert response.header.addr3 == responder.identity.mac
    assert response.ssid == dot11.STREETPASS_SSID.encode("ascii")

    tag = dot11.find_nintendo_tag(response.ies)
    assert tag is not None
    assert tag.console_id == responder.identity.console_id
    assert tag.services == [PEER_SERVICE]
    assert responder.peers[PEER_MAC] is PeerState.DISCOVERED


def test_responder_replies_to_a_real_action_frame_from_a_peer_acting_as_prober():
    """project findings (2026-09-17): handle_frame() never had a
    branch for an incoming Action frame at all -- it fell through to
    parse_probe_request(), failed, and got silently dropped. Live-captured
    against a real console A acting as prober (3 independent retries, payload
    constant at 0x0000 every time -- disproving the "must echo/increment
    like a TCP ACK" hypothesis), this was very likely why that peer's own
    handshake never advanced past an endless ~18s Action-frame retry loop."""
    responder = _responder()
    # Real capture (addr1=our session's mac that day, addr2=console A) with
    # addr1 rewritten to this test's fixed responder identity -- the header
    # layout/payload themselves are untouched real bytes.
    real_action_frame = bytes.fromhex("d000d500") + responder.identity.mac + bytes.fromhex(
        "aabbcc112233" + "ddeeff445566" + "90f3" + "7f001f320000"
    )
    peer_mac = bytes.fromhex("aabbcc112233")

    reply = responder.handle_frame(real_action_frame)

    assert len(reply) == 1
    action = dot11.parse_action_frame(reply[0])
    assert action.header.addr1 == peer_mac
    assert action.header.addr2 == responder.identity.mac
    assert action.payload == b"\x00\x00"


def test_responder_gives_consecutive_responses_increasing_sequence_numbers():
    """A real 3DS re-broadcasts its Probe Request every ~0.2-0.3s while
    continuous-scanning; a fixed seq_ctrl on every
    reply looks like a retransmission to the peer's own 802.11 duplicate
    detection and gets silently dropped after the first (§7.6, diagnosed
    live against a real console A)."""
    responder = _responder()

    first = dot11.parse_probe_response(responder.handle_frame(_peer_broadcast_probe_request())[0])
    second = dot11.parse_probe_response(responder.handle_frame(_peer_broadcast_probe_request())[0])

    assert first.header.seq_ctrl != second.header.seq_ctrl
    # fragment number (low 4 bits) stays 0; only the sequence number advances
    assert first.header.seq_ctrl & 0xF == 0
    assert second.header.seq_ctrl & 0xF == 0
    assert (second.header.seq_ctrl >> 4) == (first.header.seq_ctrl >> 4) + 1


def test_responder_replies_to_the_followup_unicast_probe_request():
    """A real second unicast Probe Request carries no Nintendo tag at all --
    just an empty SSID IE plus Supported/Extended Supported Rates -- unlike
    what was originally (incorrectly) assumed here. Confirmed live against a
    real console A."""
    responder = _responder()
    responder.handle_frame(_peer_broadcast_probe_request())

    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,
        duration=0,
        addr1=responder.identity.mac,
        addr2=PEER_MAC,
        addr3=responder.identity.mac,
        seq_ctrl=0,
    )
    ies = [
        (dot11.SSID_IE_TAG, b""),  # no SSID specified (project findings step 4)
        (dot11.SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_SUPPORTED_RATES),
        (dot11.EXTENDED_SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_EXTENDED_SUPPORTED_RATES),
    ]
    second_request = _build_probe_request(header, ies)

    reply = responder.handle_frame(second_request)

    assert len(reply) == 1
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED


def _protected_data_frame(dest: bytes, src: bytes) -> bytes:
    """A minimal protected 802.11 Data frame shell (non-QoS, ToDS=FromDS=0,
    Protected bit set) -- frame_control=0x4008, matching the real capture in
    project findings The CCMP header/ciphertext content is
    irrelevant to StreetPassResponder, which doesn't decrypt yet, so it's
    just placeholder bytes here."""
    header = dot11.ManagementFrameHeader(
        frame_control=0x4008,
        duration=0,
        addr1=dest,
        addr2=src,
        addr3=dest,
        seq_ctrl=0,
    )
    return dot11.build_management_header(header) + bytes(50)


def test_responder_marks_peer_established_on_a_real_data_frame():
    """project findings: a real peer starts sending genuine CCMP
    Data frames once it accepts our identity, even without us ever seeing
    (or replying to) a second unicast Probe Request -- StreetPassResponder
    needs to recognize that as equally proof of a completed handshake."""
    responder = _responder()
    responder.handle_frame(_peer_broadcast_probe_request())
    assert responder.peers[PEER_MAC] is PeerState.DISCOVERED

    reply = responder.handle_frame(_protected_data_frame(dest=responder.identity.mac, src=PEER_MAC))

    assert reply == []  # this responder has no keyslot_2e_key configured (§3.4.12)
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED


def test_responder_keeps_established_state_on_a_later_broadcast_probe():
    """A real peer keeps re-broadcasting its continuous-scan Probe Request
    even after the handshake has moved past that point -- observed live: re-treating one of those as a fresh
    "first contact" downgraded an already-ESTABLISHED peer back to
    DISCOVERED, which is a state machine regression, not a resync."""
    responder = _responder()
    responder.handle_frame(_peer_broadcast_probe_request())
    responder.handle_frame(_protected_data_frame(dest=responder.identity.mac, src=PEER_MAC))
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED

    reply = responder.handle_frame(_peer_broadcast_probe_request())

    assert len(reply) == 1  # still answer the peer's routine re-scan
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED


def test_responder_ignores_data_frame_from_unknown_peer():
    responder = _responder()

    reply = responder.handle_frame(_protected_data_frame(dest=responder.identity.mac, src=PEER_MAC))

    assert reply == []
    assert PEER_MAC not in responder.peers


def _responder_with_ccmp() -> StreetPassResponder:
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    return StreetPassResponder(identity=identity, services=[PEER_SERVICE], keyslot_2e_key=_TEST_KEYSLOT_2E_KEY)


def _expected_ccmp_key(responder: StreetPassResponder) -> bytes:
    hash_block = crypto.build_hash_block(
        host_console_id=responder.identity.console_id,
        client_console_id=PEER_CONSOLE_ID,
        host_mac=responder.identity.mac,
        client_mac=PEER_MAC,
    )
    return crypto.derive_ccmp_key(hash_block, responder.hmac_key, _TEST_KEYSLOT_2E_KEY)


def _syn_data_frame(responder: StreetPassResponder, key: bytes, pn: int) -> bytes:
    plaintext = sptcp.MSDU_PREAMBLE + sptcp.build_handshake_packet(sptcp.FLAG_SYN)
    return ccmp.build_data_frame(
        dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=pn, key=key, plaintext=plaintext,
    )


def test_responder_decrypts_a_syn_and_replies_synack():
    """project findings: with a keyslot_2e_key configured, a real
    peer's SPTCP SYN (§3.4.7's real captured plaintext) should now get a
    real SYN+ACK back, CCMP-encrypted with the same session key."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())  # captures PEER_CONSOLE_ID, marks DISCOVERED
    key = _expected_ccmp_key(responder)

    reply = responder.handle_frame(_syn_data_frame(responder, key, pn=1))

    assert len(reply) == 1
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED
    decrypted = ccmp.decrypt_data_frame(reply[0], key)
    assert decrypted.pn == 1  # our first frame to this peer
    assert decrypted.dest == PEER_MAC
    reply_header = sptcp.parse_header(decrypted.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == sptcp.FLAG_SYN | sptcp.FLAG_ACK


def test_responder_increments_pn_across_replies_to_the_same_peer():
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)

    first = responder.handle_frame(_syn_data_frame(responder, key, pn=1))
    second = responder.handle_frame(_syn_data_frame(responder, key, pn=2))

    assert ccmp.decrypt_data_frame(first[0], key).pn == 1
    assert ccmp.decrypt_data_frame(second[0], key).pn == 2


def test_responder_does_not_reply_when_ccmp_key_is_wrong():
    """A wrong/stale key (e.g. the peer's consoleID/MAC rotated) should fail MIC verification quietly rather than crash the pipeline."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    wrong_key = bytes(16)

    reply = responder.handle_frame(_syn_data_frame(responder, wrong_key, pn=1))

    assert reply == []
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED  # state still updates


def test_responder_does_not_reply_without_keyslot_2e_key():
    responder = _responder()  # no keyslot_2e_key
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(_responder_with_ccmp())

    reply = responder.handle_frame(_syn_data_frame(responder, key, pn=1))

    assert reply == []
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED


def test_responder_ignores_unprotected_data_frame():
    responder = _responder()
    responder.handle_frame(_peer_broadcast_probe_request())

    header = dot11.ManagementFrameHeader(
        frame_control=0x0008,  # Data, Protected bit NOT set
        duration=0,
        addr1=responder.identity.mac,
        addr2=PEER_MAC,
        addr3=responder.identity.mac,
        seq_ctrl=0,
    )
    frame = dot11.build_management_header(header) + bytes(50)

    responder.handle_frame(frame)

    assert responder.peers[PEER_MAC] is PeerState.DISCOVERED


def test_responder_ignores_unicast_probe_from_unknown_peer():
    responder = _responder()
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,
        duration=0,
        addr1=responder.identity.mac,
        addr2=bytes.fromhex("999999999999"),
        addr3=responder.identity.mac,
        seq_ctrl=0,
    )
    nintendo_tag = dot11.build_nintendo_tag([PEER_SERVICE], bytes(8))
    ies = [
        (dot11.SSID_IE_TAG, b""),
        (dot11.VENDOR_SPECIFIC_IE_TAG, dot11.NINTENDO_OUI + bytes([dot11.NINTENDO_OUI_TYPE]) + nintendo_tag),
    ]
    frame = _build_probe_request(header, ies)

    assert responder.handle_frame(frame) == []


def test_responder_ignores_non_probe_frames():
    responder = _responder()
    assert responder.handle_frame(bytes(30)) == []


def test_responder_ignores_wrong_ssid():
    responder = _responder()
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,
        duration=0,
        addr1=dot11.BROADCAST_MAC,
        addr2=PEER_MAC,
        addr3=dot11.BROADCAST_MAC,
        seq_ctrl=0,
    )
    ies = [(dot11.SSID_IE_TAG, b"SomeOtherNetwork")]
    frame = _build_probe_request(header, ies)

    assert responder.handle_frame(frame) == []


def test_responder_ignores_probe_without_nintendo_tag():
    responder = _responder()
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,
        duration=0,
        addr1=dot11.BROADCAST_MAC,
        addr2=PEER_MAC,
        addr3=dot11.BROADCAST_MAC,
        seq_ctrl=0,
    )
    ies = [(dot11.SSID_IE_TAG, dot11.STREETPASS_SSID.encode("ascii"))]
    frame = _build_probe_request(header, ies)

    assert responder.handle_frame(frame) == []


def _spmtp_data_frame(responder: StreetPassResponder, key: bytes, pn: int, spmtp_payload: bytes) -> bytes:
    """A complete (non-fragmented) SPTCP packet carrying an SPMTP payload,
    flags=PSH+ACK+END -- the shape a real Info SPMTP handshake message
    arrives in."""
    sptcp_body = sptcp.build_packet(sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, spmtp_payload)
    plaintext = sptcp.MSDU_PREAMBLE + sptcp_body
    return ccmp.build_data_frame(
        dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=pn, key=key, plaintext=plaintext,
    )


def _peer_identity_client_payload() -> bytes:
    identity = spmtp.IdentityPacket(
        transferable_id=bytes.fromhex("aabbccddeeff0011"),
        session_id=0x12345678,
        original_mac=bytes.fromhex("445566778899"),
        timestamp=bytes(12),
    )
    header = spmtp.HandshakeHeader(packet_type=spmtp.PacketType.IDENTITY_CLIENT, content_size=spmtp.IdentityPacket.SIZE)
    return spmtp.build_handshake_header(header) + spmtp.build_identity_packet(identity)


def _handshake_data_frame(responder: StreetPassResponder, key: bytes, pn: int, flags: int, bytes_received: int = 0) -> bytes:
    plaintext = sptcp.MSDU_PREAMBLE + sptcp.build_packet(flags, bytes_received=bytes_received)
    return ccmp.build_data_frame(
        dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=pn, key=key, plaintext=plaintext,
    )


def test_responder_acks_then_initiates_its_own_handshake_before_replying_with_identity():
    """project findings: a real peer expects the sender of *every*
    SPMTP message -- us included, replying with our own Identity -- to run
    a fresh 3-way handshake immediately before that message, not just once
    for the whole conversation (which was still wrong even after §7.9's
    ACK/data split). So: their Identity Client -> our ACK (bytes_received
    set to what we received) + our own handshake SYN; their SYN+ACK reply
    -> our final ACK + our actual Identity Master payload."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    identity_client_payload = _peer_identity_client_payload()

    first_reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=identity_client_payload))

    assert len(first_reply) == 2
    ack = ccmp.decrypt_data_frame(first_reply[0], key)
    assert ack.pn == 1
    ack_header, ack_payload = sptcp.parse_packet(ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert ack_header.flags == sptcp.FLAG_ACK
    assert ack_header.bytes_received == len(identity_client_payload)
    assert ack_payload == b""
    syn = ccmp.decrypt_data_frame(first_reply[1], key)
    assert syn.pn == 2
    syn_header, _ = sptcp.parse_packet(syn.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert syn_header.flags == sptcp.FLAG_SYN

    # Peer answers our handshake SYN with a SYN+ACK.
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert len(second_reply) == 2
    final_ack = ccmp.decrypt_data_frame(second_reply[0], key)
    assert final_ack.pn == 3
    final_ack_header, _ = sptcp.parse_packet(final_ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert final_ack_header.flags == sptcp.FLAG_ACK
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    assert data.pn == 4
    reply_header, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END
    spmtp_header = spmtp.parse_handshake_header(reply_payload)
    assert spmtp_header.packet_type == spmtp.PacketType.IDENTITY_MASTER
    identity = spmtp.parse_identity_packet(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:])
    assert identity.transferable_id == responder.identity.transferable_id
    assert identity.session_id == responder.identity.session_id
    assert identity.original_mac == responder.identity.original_mac


def test_responder_ignores_unexpected_synack():
    """A SYN+ACK we weren't waiting for (no queued outgoing payload) --
    e.g. a stray retransmission -- shouldn't produce a response."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)

    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=1, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert reply == []


def test_responder_bare_acks_an_unrecognized_spmtp_packet():
    """Every packet type in the fixed order that a
    peer can actually send us (i.e. every _CLIENT type, plus 0x81/0x43 which
    aren't client/master-split) is handled -- this uses an arbitrary type
    number outside that set to exercise the fallback: still SPTCP-ACK it (so
    a real peer stops retransmitting) rather than silently drop it, per
    "受信側はACKを返す". No reply payload to send means no second packet,
    unlike the Identity case."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    unrecognized_header = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=0x99, content_size=0)
    )

    reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=unrecognized_header))

    assert len(reply) == 1
    decrypted = ccmp.decrypt_data_frame(reply[0], key)
    reply_header, reply_payload = sptcp.parse_packet(decrypted.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == sptcp.FLAG_ACK
    assert reply_payload == b""


def test_responder_ignores_the_handshakes_final_bare_ack():
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    plaintext = sptcp.MSDU_PREAMBLE + sptcp.build_handshake_packet(sptcp.FLAG_ACK)
    frame = ccmp.build_data_frame(dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=1, key=key, plaintext=plaintext)

    assert responder.handle_frame(frame) == []


def test_responder_accepts_peers_identity_accept_with_its_own():
    """project findings: live-verified -- after the peer ACKs our
    Identity Master reply, it sends its own Identity Accept (0x43) as the
    next message in the fixed order (0x41, 0x42, 0x43, 0x43, ...). We must
    reply in kind: our own handshake SYN, then (once they SYN+ACK it) our
    own 0x43 Identity Accept payload."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_identity_accept_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.IDENTITY_ACCEPT, content_size=spmtp.IDENTITY_ACCEPT_SIZE)
    ) + spmtp.build_identity_accept_packet()

    first_reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_identity_accept_payload))

    assert len(first_reply) == 2
    ack = ccmp.decrypt_data_frame(first_reply[0], key)
    ack_header, ack_payload = sptcp.parse_packet(ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert ack_header.flags == sptcp.FLAG_ACK
    assert ack_header.bytes_received == len(peer_identity_accept_payload)
    assert ack_payload == b""
    syn = ccmp.decrypt_data_frame(first_reply[1], key)
    syn_header, _ = sptcp.parse_packet(syn.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert syn_header.flags == sptcp.FLAG_SYN

    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    reply_header, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END
    reply_spmtp_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_spmtp_header.packet_type == spmtp.PacketType.IDENTITY_ACCEPT
    assert reply_spmtp_header.content_size == spmtp.IDENTITY_ACCEPT_SIZE
    assert reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:] == spmtp.build_identity_accept_packet()


def test_responder_answers_module_filter_with_its_own_nintendo_tag():
    """project findings: live-verified -- Module Filter Client's
    content is exactly a Nintendo tag (dot11.build_nintendo_tag()'s output,
    the same services+consoleID structure as the Probe Request IE). We
    should answer with our own Nintendo tag, following the same
    handshake-then-reply pattern as Identity/Identity Accept."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_nintendo_tag = dot11.build_nintendo_tag([PEER_SERVICE], PEER_CONSOLE_ID)
    module_filter_client_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MODULE_FILTER_CLIENT, content_size=len(peer_nintendo_tag))
    ) + peer_nintendo_tag

    first_reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=module_filter_client_payload))

    assert len(first_reply) == 2
    ack = ccmp.decrypt_data_frame(first_reply[0], key)
    ack_header, ack_payload = sptcp.parse_packet(ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert ack_header.flags == sptcp.FLAG_ACK
    assert ack_header.bytes_received == len(module_filter_client_payload)
    assert ack_payload == b""

    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    reply_header, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END
    reply_spmtp_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_spmtp_header.packet_type == spmtp.PacketType.MODULE_FILTER_MASTER
    our_tag = dot11.parse_nintendo_tag(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:])
    assert our_tag.services == [PEER_SERVICE]
    assert our_tag.console_id == responder.identity.console_id


def test_responder_answers_friend_code_with_an_honest_zero():
    """project findings: we have no real Nintendo Network friend code
    to disclose, so we answer with 0 rather than fabricating one."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_friend_code_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.FRIEND_CODE_CLIENT, content_size=8)
    ) + spmtp.build_friend_code_packet(spmtp.FriendCodePacket(friend_code=123456789012))

    first_reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_friend_code_payload))
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    reply_header, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    reply_spmtp_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_spmtp_header.packet_type == spmtp.PacketType.FRIEND_CODE_MASTER
    friend_code = spmtp.parse_friend_code_packet(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:])
    assert friend_code.friend_code == 0


def test_responder_discloses_a_configured_friend_code():
    """project findings: a real, checksum-valid friend code passed via
    StreetPassResponder(friend_code=...) gets disclosed instead of the
    honest-zero default."""
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    configured_friend_code = spmtp.friend_code_value_from_string("4126-2228-0312")
    responder = StreetPassResponder(
        identity=identity, services=[PEER_SERVICE], keyslot_2e_key=_TEST_KEYSLOT_2E_KEY, friend_code=configured_friend_code,
    )
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_friend_code_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.FRIEND_CODE_CLIENT, content_size=8)
    ) + spmtp.build_friend_code_packet(spmtp.FriendCodePacket(friend_code=123456789012))

    responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_friend_code_payload))
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    data = ccmp.decrypt_data_frame(second_reply[1], key)
    _, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    friend_code = spmtp.parse_friend_code_packet(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:])
    assert friend_code.friend_code == configured_friend_code


def test_responder_answers_friend_flag_saying_not_a_friend():
    """project findings: we've never seen this peer before, so "not a
    friend" (flag=0) is simply true."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_friend_flag_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.FRIEND_FLAG_CLIENT, content_size=4)
    ) + spmtp.build_friend_flag_packet(spmtp.FriendFlagPacket(flag=1))

    first_reply = responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_friend_flag_payload))
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    reply_header, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    reply_spmtp_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_spmtp_header.packet_type == spmtp.PacketType.FRIEND_FLAG_MASTER
    friend_flag = spmtp.parse_friend_flag_packet(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:])
    assert friend_flag.flag == 0


def _complete_reply_round_trip(responder: StreetPassResponder, key: bytes, request_payload: bytes) -> bytes:
    """Drives one full request/reply exchange (project findings's
    per-message-handshake pattern) and returns our reply's raw SPMTP
    payload. Shared by the Message Box / TMP Box tests below, which all
    follow the same shape as the Identity/Module Filter/Friend Code tests
    above but don't need to inspect the intermediate ACK frames."""
    responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=request_payload))
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    _, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
    return reply_payload


def test_responder_answers_message_box_metadata_list_with_an_empty_list():
    """project findings: no real StreetPass game data to advertise, so
    an empty list is the honest answer, not a placeholder."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00020800, send_mode=0, flag=0, send_state=0, send_size=100, message_count=1
    )
    peer_list_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT, content_size=0x2C + 0x20)
    ) + spmtp.build_message_box_metadata_list([peer_entry])

    reply_payload = _complete_reply_round_trip(responder, key, peer_list_payload)

    reply_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_header.packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_MASTER
    assert spmtp.parse_message_box_metadata_list(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:]) == []


def test_responder_answers_message_box_metadata_parsed_with_an_empty_list_when_peer_offered_nothing():
    """project findings: if the peer's own 0x31 never listed anything
    (or, as here, was skipped entirely), there's nothing to want -- an
    empty "parsed" list back."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_parsed_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT, content_size=0x2C)
    ) + spmtp.build_message_box_metadata_list([])

    reply_payload = _complete_reply_round_trip(responder, key, peer_parsed_payload)

    reply_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_header.packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_MASTER
    assert spmtp.parse_message_box_metadata_list(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:]) == []


def test_responder_requests_a_peer_message_matching_a_supported_service():
    """: a live capture showed a real peer's
    0x31 list isn't necessarily empty -- console A had one real queued Mii
    Plaza message (title_id 0x00020800, matching MII_PLAZA_SERVICE/
    PEER_SERVICE, which this responder's `services` declares support for
    via Module Filter). We should echo that entry back (with send_state set
    to 1, project findings's field table calling it "modified by peer
    when sent back") in our 0x34 "parsed" reply to the peer's *original*
    0x31 list (remembered from before, not the empty 0x33 this test also
    sends), declaring interest -- and leave out any entry for a title we
    don't support."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    wanted_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00020800, send_mode=0, flag=3, send_state=0, send_size=32692, message_count=1
    )
    unsupported_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00099999, send_mode=0, flag=3, send_state=0, send_size=100, message_count=1
    )
    peer_list_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT, content_size=0x2C + 0x40)
    ) + spmtp.build_message_box_metadata_list([wanted_entry, unsupported_entry])
    responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_list_payload))
    responder.handle_frame(_handshake_data_frame(responder, key, pn=3, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))

    peer_parsed_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT, content_size=0x2C)
    ) + spmtp.build_message_box_metadata_list([])
    responder.handle_frame(_spmtp_data_frame(responder, key, pn=5, spmtp_payload=peer_parsed_payload))
    second_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=7, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
    assert len(second_reply) == 2
    data = ccmp.decrypt_data_frame(second_reply[1], key)
    _, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])

    reply_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_header.packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_MASTER
    expected_entry = replace(wanted_entry, send_state=1)
    assert spmtp.parse_message_box_metadata_list(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:]) == [expected_entry]


def test_responder_answers_tmp_box_metadata_list_with_an_empty_list():
    """project findings: 0x81 is sent by both sides using the same
    packet type -- we always reply in kind with our own empty list."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    peer_entry = spmtp.TmpBoxMetadataEntry(title_id=0x00020800, size=1234)
    peer_tmp_box_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.TMP_BOX_METADATA_LIST, content_size=4 + 8)
    ) + spmtp.build_tmp_box_metadata_list([peer_entry])

    reply_payload = _complete_reply_round_trip(responder, key, peer_tmp_box_payload)

    reply_header = spmtp.parse_handshake_header(reply_payload)
    assert reply_header.packet_type == spmtp.PacketType.TMP_BOX_METADATA_LIST
    assert spmtp.parse_tmp_box_metadata_list(reply_payload[spmtp.HANDSHAKE_HEADER_SIZE:]) == []


def test_responder_closes_the_conversation_with_ack_fin():
    """project findings: once the peer ACKs our last reply with FIN
    set too (both sides have declared they have nothing left to send), we
    close out in kind with our own ACK+FIN -- no handshake needed, same as
    any other bare-ACK-level reply."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)

    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=1, flags=sptcp.FLAG_ACK | sptcp.FLAG_FIN))

    assert len(reply) == 1
    decrypted = ccmp.decrypt_data_frame(reply[0], key)
    reply_header, reply_payload = sptcp.parse_packet(decrypted.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == (sptcp.FLAG_ACK | sptcp.FLAG_FIN)
    assert reply_payload == b""


def test_responder_closes_the_conversation_with_bare_fin():
    """project findings: a live capture showed a real peer close with
    a *bare* FIN (no ACK bit), not the ACK+FIN project findings's
    Conversation Flow quote described -- we answer the same way either
    time, with our own ACK+FIN."""
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)

    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=1, flags=sptcp.FLAG_FIN))

    assert len(reply) == 1
    decrypted = ccmp.decrypt_data_frame(reply[0], key)
    reply_header, reply_payload = sptcp.parse_packet(decrypted.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert reply_header.flags == (sptcp.FLAG_ACK | sptcp.FLAG_FIN)
    assert reply_payload == b""


def _tmp_box_data_frame(responder: StreetPassResponder, key: bytes, pn: int, flags: int, payload: bytes, bytes_sent: int) -> bytes:
    """A raw "Message Box SPMTP" fragment -- unlike
    _spmtp_data_frame(), this carries no HANDSHAKE_MAGIC at all, the shape
    real TMP Box download chunks arrive in."""
    sptcp_body = sptcp.build_packet(flags, payload, bytes_sent=bytes_sent)
    plaintext = sptcp.MSDU_PREAMBLE + sptcp_body
    return ccmp.build_data_frame(
        dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=pn, key=key, plaintext=plaintext,
    )


def test_responder_reassembles_a_tmp_box_download_across_multiple_windows(monkeypatch):
    """: a live capture showed a real TMP Box
    download segmented into TMP_BOX_WINDOW_SIZE-byte windows -- each made
    of several packets, only the last (PSH+ACK+END) of which gets ACKed.
    bytes_sent is cumulative across the *whole* transfer (§7.40 -- §7.23's
    original "relative to the current window" reading was never actually
    exercised past window 1 until a real transfer finally advanced beyond
    it). This patches the window size down to 8 (two 4-byte packets per
    window) so the test doesn't need to push tens of kilobytes through."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    body = bytes(range(20))  # 20 bytes of TMP Box content after the header
    tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=0x00020800, group_id=0, message_count=1)
    ) + body
    assert len(tmp_box) == 40  # exactly 5 windows of 8 bytes, with the patched window size

    pn = 1
    for window_start in range(0, len(tmp_box), 8):
        window = tmp_box[window_start:window_start + 8]
        first_half, second_half = window[:4], window[4:]
        reply = responder.handle_frame(
            _tmp_box_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, payload=first_half, bytes_sent=window_start)
        )
        assert reply == []  # mid-window packet: buffered, no reply
        pn += 1
        reply = responder.handle_frame(
            _tmp_box_data_frame(
                responder, key, pn=pn, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END,
                payload=second_half, bytes_sent=window_start + 4,
            )
        )
        pn += 1
        assert len(reply) == 1  # only the window's last packet gets ACKed
        ack = ccmp.decrypt_data_frame(reply[0], key)
        ack_header, _ = sptcp.parse_packet(ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
        # project findings: cumulative across the whole transfer so
        # far (bytes_sent of this last packet + its own length), not just
        # this packet's own length -- here they'd coincide within a single
        # window since bytes_sent resets each time, so this only actually
        # differs from window_start+4+len(second_half) once more than one
        # window has gone by; test_responder_acks_the_full_cumulative_
        # window_size_not_just_the_last_packet below isolates a single
        # window with uneven packet sizes to tell the two apart for real.
        assert ack_header.bytes_received == window_start + len(window)

    assert responder.completed_tmp_boxes[PEER_MAC] == [tmp_box]


def test_responder_acks_the_full_cumulative_window_size_not_just_the_last_packet(monkeypatch):
    """project findings: 3dbrew's own text (quoted in §7.12) says this
    ACK must carry "the number of payload bytes received from the current
    SPMTP *until that point*" -- cumulative, symmetric with bytes_sent. A
    live capture showed a real peer stuck endlessly re-sending window 1
    from scratch, consistent with it reading our previous (buggy) len(this
    packet only) as "you're missing the rest of the window". Uses uneven
    packet sizes (3 then 5, an 8-byte window) so a last-packet-only
    ack (5) is distinguishable from the correct cumulative one (8)."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    first, second = bytes(range(3)), bytes(range(3, 8))

    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=1, flags=sptcp.FLAG_ACK, payload=first, bytes_sent=0)
    )
    reply = responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=2, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=second, bytes_sent=3)
    )
    assert len(reply) == 1
    ack = ccmp.decrypt_data_frame(reply[0], key)
    ack_header, _ = sptcp.parse_packet(ack.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert ack_header.bytes_received == 8  # the whole window (3+5), not just len(second)==5


def test_responder_discards_a_partial_window_on_retry(monkeypatch):
    """: a live capture showed RF loss make a
    window get resent from scratch rather than resumed -- since bytes_sent
    is cumulative across the whole transfer (§7.40), retrying window 2
    means resending starting from cumulative position 8 again (window 2's
    own start), not resetting to 0 (that would mean restarting the *whole*
    transfer instead). Confirms a garbage attempt that happens to reach a
    full window's length without ever getting its PSH+ACK+END gets
    discarded -- overwritten by the retry's real content -- rather than
    corrupting what follows."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    body = bytes(range(4))
    tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=0x00020800, group_id=0, message_count=1)
    ) + body
    assert len(tmp_box) == 24  # window 1 (8 bytes) + window 2 (8 bytes) + a final 8-byte window

    # Window 1 completes normally.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=1, flags=sptcp.FLAG_ACK, payload=tmp_box[0:4], bytes_sent=0))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=2, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[4:8], bytes_sent=4)
    )
    # Window 2: a garbage attempt that reaches a full window's length (8
    # bytes) but never gets its PSH+ACK+END -- it must not be mistaken for
    # a completed window just because the length happens to line up.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=3, flags=sptcp.FLAG_ACK, payload=b"\xff\xff\xff\xff", bytes_sent=8))
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=4, flags=sptcp.FLAG_ACK, payload=b"\xff\xff\xff\xff", bytes_sent=12))
    # Window 2 retried from its own start (cumulative position 8, not a
    # full-transfer restart to 0) -- the garbage above must be discarded.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=5, flags=sptcp.FLAG_ACK, payload=tmp_box[8:12], bytes_sent=8))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=6, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[12:16], bytes_sent=12)
    )
    # Window 3 (final, exactly one window).
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=7, flags=sptcp.FLAG_ACK, payload=tmp_box[16:20], bytes_sent=16))
    reply = responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=8, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[20:24], bytes_sent=20)
    )

    assert len(reply) == 1
    assert responder.completed_tmp_boxes[PEER_MAC] == [tmp_box]


def test_responder_ignores_a_retransmit_of_an_already_confirmed_window(monkeypatch):
    """project findings: a live capture showed the peer resend a
    window it had *already sent completely and gotten ACKed* (most likely
    because that ACK didn't reach it), not just a still-in-progress one --
    here, a full-transfer restart back to cumulative position 0 (§7.40)
    after window 1 was already confirmed. Before this was handled, the
    resend got appended as if it were the *next* window's data, corrupting
    the reassembled TMP Box (confirmed live: a real download came back
    6805 bytes different from a known-good reference capture, first
    diverging partway through the "opaque" region right after the
    duplicated window's worth of bytes) -- reproduced here with a synthetic
    resend and confirmed fixed by checking the final result matches what
    window 1 + window 2 (once, not twice) should be."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    body = bytes(range(4))
    tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=0x00020800, group_id=0, message_count=1)
    ) + body
    assert len(tmp_box) == 24  # window 1 (8) + window 2 (8) + a final 8-byte window

    # Window 1 completes normally.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=1, flags=sptcp.FLAG_ACK, payload=tmp_box[0:4], bytes_sent=0))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=2, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[4:8], bytes_sent=4)
    )
    # Window 1 gets resent in full, from scratch -- *after* already being
    # confirmed. Without the fix, this would be appended as more data past
    # what's already there, corrupting the buffer.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=3, flags=sptcp.FLAG_ACK, payload=tmp_box[0:4], bytes_sent=0))
    reply = responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=4, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[4:8], bytes_sent=4)
    )
    assert len(reply) == 1  # still ACKed, just not appended
    assert bytes(responder._sessions[PEER_MAC].tmp_box_buffer) == tmp_box[0:8]  # unchanged by the resend
    # Window 2 (genuinely new content) completes normally.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=5, flags=sptcp.FLAG_ACK, payload=tmp_box[8:12], bytes_sent=8))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=6, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[12:16], bytes_sent=12)
    )
    # Window 3 (final).
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=7, flags=sptcp.FLAG_ACK, payload=tmp_box[16:20], bytes_sent=16))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=8, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[20:24], bytes_sent=20)
    )

    assert responder.completed_tmp_boxes[PEER_MAC] == [tmp_box]


def test_responder_ignores_a_retransmit_missing_its_own_bytes_sent_zero_packet(monkeypatch):
    """project findings: a live capture showed RF loss can drop the
    bytes_sent==0 packet of a retransmitted, already-confirmed window too --
    so *only* its tail (bytes_sent > 0) is ever seen, with no bytes_sent==0
    packet to key a "this is a resend" check off of at all. Confirms the
    fix (comparing every packet's content against confirmed history by
    position, not just packets that happen to arrive at bytes_sent==0)
    catches this orphaned-tail case too."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    body = bytes(range(4))
    tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=0x00020800, group_id=0, message_count=1)
    ) + body
    assert len(tmp_box) == 24  # window 1 (8) + window 2 (8) + a final 8-byte window

    # Window 1 completes normally.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=1, flags=sptcp.FLAG_ACK, payload=tmp_box[0:4], bytes_sent=0))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=2, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[4:8], bytes_sent=4)
    )
    # Window 1 gets resent, but its own bytes_sent=0 packet is lost to RF --
    # we only ever see this trailing (bytes_sent=4) packet of that resend.
    # Without the fix, this gets blindly appended (there's no bytes_sent==0
    # arrival to trigger any check at all), corrupting the reassembly.
    reply = responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=3, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[4:8], bytes_sent=4)
    )
    assert len(reply) == 1  # still ACKed, just not appended
    assert bytes(responder._sessions[PEER_MAC].tmp_box_buffer) == tmp_box[0:8]  # unchanged by the orphaned tail
    # Window 2 (genuinely new content) completes normally.
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=4, flags=sptcp.FLAG_ACK, payload=tmp_box[8:12], bytes_sent=8))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=5, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[12:16], bytes_sent=12)
    )
    # Window 3 (final).
    responder.handle_frame(_tmp_box_data_frame(responder, key, pn=6, flags=sptcp.FLAG_ACK, payload=tmp_box[16:20], bytes_sent=16))
    responder.handle_frame(
        _tmp_box_data_frame(responder, key, pn=7, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, payload=tmp_box[20:24], bytes_sent=20)
    )

    assert responder.completed_tmp_boxes[PEER_MAC] == [tmp_box]


def test_responder_sends_an_outbound_tmp_box_when_the_peer_wants_it(monkeypatch):
    """project findings: this project's first outbound Message/TMP
    Box content -- full round trip: we advertise outbound_message_box_entry
    in our 0x32, the peer's 0x33 names its title (declaring interest), we
    advertise it again in our 0x81, and once *that* reply is itself
    acknowledged session.queued_send fires: we initiate our own handshake
    and push outbound_tmp_box's bytes, unprompted by anything the peer
    sends other than that ACK."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 4096)  # plenty for this tiny test box
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    outbound_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00020800, send_mode=0, flag=0, send_state=0, send_size=100, message_count=1
    )
    outbound_tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + 4, title_id=0x00020800, group_id=0, message_count=1)
    ) + b"\xde\xad\xbe\xef"
    responder = StreetPassResponder(
        identity=identity, services=[PEER_SERVICE], keyslot_2e_key=_TEST_KEYSLOT_2E_KEY,
        outbound_message_box_entry=outbound_entry, outbound_tmp_box=outbound_tmp_box,
    )
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    pn = 1

    def send(spmtp_payload):
        nonlocal pn
        responder.handle_frame(_spmtp_data_frame(responder, key, pn=pn, spmtp_payload=spmtp_payload))
        pn += 1
        reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
        pn += 1
        assert len(reply) == 2
        data = ccmp.decrypt_data_frame(reply[1], key)
        _, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
        return reply_payload

    # Peer's own list is empty -- we still offer ours.
    peer_list_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT, content_size=0x2C)
    ) + spmtp.build_message_box_metadata_list([])
    our_032 = send(peer_list_payload)
    assert spmtp.parse_handshake_header(our_032).packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_MASTER
    assert spmtp.parse_message_box_metadata_list(our_032[spmtp.HANDSHAKE_HEADER_SIZE:]) == [outbound_entry]

    # Peer's 0x33 names our title -- declaring interest in what we offered.
    peer_033_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT, content_size=0x4C)
    ) + spmtp.build_message_box_metadata_list([outbound_entry])
    send(peer_033_payload)
    assert responder._sessions[PEER_MAC].peer_wants_our_tmp_box is True

    # Peer's own TMP Box list is empty -- we still offer + queue ours.
    peer_081_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.TMP_BOX_METADATA_LIST, content_size=4)
    ) + spmtp.build_tmp_box_metadata_list([])
    our_081 = send(peer_081_payload)
    assert spmtp.parse_handshake_header(our_081).packet_type == spmtp.PacketType.TMP_BOX_METADATA_LIST
    assert spmtp.parse_tmp_box_metadata_list(our_081[spmtp.HANDSHAKE_HEADER_SIZE:]) == [
        spmtp.TmpBoxMetadataEntry(title_id=outbound_entry.title_id, size=len(outbound_tmp_box))
    ]
    assert responder._sessions[PEER_MAC].queued_send == outbound_tmp_box

    # The peer bare-ACKs our 0x81 (bytes_received covering all of it, docs/
    # PROTOCOL.md §7.38/§7.41 -- this closes out that send in our own
    # bookkeeping too) -- nothing else prompts what happens next.
    reply = responder.handle_frame(
        _handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, bytes_received=len(our_081))
    )
    assert len(reply) == 1  # just our handshake SYN, initiating our own send
    syn = ccmp.decrypt_data_frame(reply[0], key)
    syn_header, _ = sptcp.parse_packet(syn.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert syn_header.flags == sptcp.FLAG_SYN
    assert responder._sessions[PEER_MAC].pending_outgoing_payload == outbound_tmp_box
    assert responder._sessions[PEER_MAC].queued_send is None

    pn += 1
    final_reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
    assert len(final_reply) == 2
    sent_box = ccmp.decrypt_data_frame(final_reply[1], key)
    sent_header, sent_payload = sptcp.parse_packet(sent_box.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert sent_header.flags == sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END
    assert sent_payload == outbound_tmp_box


def test_responder_sends_a_multi_window_outbound_payload(monkeypatch):
    """project findings: an outbound send larger than one packet needs
    the same windowed shape a real console's own sends use (docs/
    PROTOCOL.md §7.40) -- before this, any payload_to_send() went out as a
    single, arbitrarily large packet, never actually exercised past the
    ~3KB experimental payloads used before a real 32712-byte TMP Box
    download ever worked live. Patches both the window and per-packet
    sizes down so a 3-window transfer (2 full windows of 2 packets each,
    then a 1-packet partial window) fits in a small synthetic payload."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    monkeypatch.setattr(session_module, "TMP_BOX_PACKET_PAYLOAD_SIZE", 4)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    payload = bytes(range(20))  # window 1 (0:8), window 2 (8:16), window 3 (16:20)
    responder._sessions[PEER_MAC].pending_outgoing_payload = payload

    def decrypt_all(frames):
        parsed = []
        for f in frames:
            d = ccmp.decrypt_data_frame(f, key)
            hdr, pl = sptcp.parse_packet(d.plaintext[len(sptcp.MSDU_PREAMBLE):])
            parsed.append((hdr, pl))
        return parsed

    pn = 1
    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
    parsed = decrypt_all(reply)
    assert len(parsed) == 3  # our closing ACK for the handshake, then window 1's 2 packets
    assert parsed[0][0].flags == sptcp.FLAG_ACK and parsed[0][1] == b""
    assert (parsed[1][0].flags, parsed[1][0].bytes_sent, parsed[1][1]) == (sptcp.FLAG_ACK, 0, payload[0:4])
    assert (parsed[2][0].flags, parsed[2][0].bytes_sent, parsed[2][1]) == (
        sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, 4, payload[4:8],
    )

    pn += 1
    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, bytes_received=8))
    parsed = decrypt_all(reply)
    assert len(parsed) == 2  # window 2, unprompted by anything but that ACK
    assert (parsed[0][0].bytes_sent, parsed[0][1]) == (8, payload[8:12])
    assert (parsed[1][0].flags, parsed[1][0].bytes_sent, parsed[1][1]) == (
        sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, 12, payload[12:16],
    )

    pn += 1
    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, bytes_received=16))
    parsed = decrypt_all(reply)
    assert len(parsed) == 1  # window 3: a single, partial (4-byte) window
    assert (parsed[0][0].flags, parsed[0][0].bytes_sent, parsed[0][1]) == (
        sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END, 16, payload[16:20],
    )

    pn += 1
    reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, bytes_received=20))
    assert reply == []  # fully sent, nothing queued behind it
    assert responder._sessions[PEER_MAC].outbound_send_payload is None


def test_responder_defers_its_own_send_until_the_peers_download_finishes(monkeypatch):
    """project findings: a live capture showed firing our own
    outbound send the moment our 0x81 reply is bare-ACKed collides with the
    peer's own concurrent send-initiation for the TMP Box IT offered in
    that same 0x81 -- real hardware got stuck endlessly retransmitting its
    own first window instead of replying to our SYN. So when the peer's
    0x81 list isn't empty, our queued_send must wait until its download to
    us actually finishes (_handle_tmp_box_data), not fire on the bare ACK."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 4096)
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    outbound_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00020800, send_mode=0, flag=0, send_state=0, send_size=100, message_count=1
    )
    outbound_tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + 4, title_id=0x00020800, group_id=0, message_count=1)
    ) + b"\xde\xad\xbe\xef"
    responder = StreetPassResponder(
        identity=identity, services=[PEER_SERVICE], keyslot_2e_key=_TEST_KEYSLOT_2E_KEY,
        outbound_message_box_entry=outbound_entry, outbound_tmp_box=outbound_tmp_box,
    )
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)
    pn = 1

    def send(spmtp_payload):
        nonlocal pn
        responder.handle_frame(_spmtp_data_frame(responder, key, pn=pn, spmtp_payload=spmtp_payload))
        pn += 1
        reply = responder.handle_frame(_handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_SYN | sptcp.FLAG_ACK))
        pn += 1
        assert len(reply) == 2
        data = ccmp.decrypt_data_frame(reply[1], key)
        _, reply_payload = sptcp.parse_packet(data.plaintext[len(sptcp.MSDU_PREAMBLE):])
        return reply_payload

    peer_list_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT, content_size=0x2C)
    ) + spmtp.build_message_box_metadata_list([])
    send(peer_list_payload)

    peer_033_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT, content_size=0x4C)
    ) + spmtp.build_message_box_metadata_list([outbound_entry])
    send(peer_033_payload)
    assert responder._sessions[PEER_MAC].peer_wants_our_tmp_box is True

    # Peer's own 0x81 list is NOT empty this time -- it has a box of its own.
    peer_tmp_box = spmtp.build_tmp_box_header(
        spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + 4, title_id=0x00020900, group_id=0, message_count=1)
    ) + b"\xca\xfe\xba\xbe"
    peer_entry = spmtp.TmpBoxMetadataEntry(title_id=0x00020900, size=len(peer_tmp_box))
    peer_081_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.TMP_BOX_METADATA_LIST, content_size=4)
    ) + spmtp.build_tmp_box_metadata_list([peer_entry])
    our_081 = send(peer_081_payload)
    assert responder._sessions[PEER_MAC].queued_send == outbound_tmp_box
    assert responder._sessions[PEER_MAC].tmp_box_download_pending is True

    # The peer bare-ACKs our 0x81 (bytes_received covering all of it, docs/
    # PROTOCOL.md §7.38/§7.41) -- but its own download is still pending, so
    # we must NOT initiate our own send yet (this is the bug: previously
    # this fired a colliding SYN right here).
    reply = responder.handle_frame(
        _handshake_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, bytes_received=len(our_081))
    )
    pn += 1
    assert reply == []
    assert responder._sessions[PEER_MAC].queued_send == outbound_tmp_box  # still queued, not fired

    # The peer now actually sends us its own TMP Box.
    reply = responder.handle_frame(
        _tmp_box_data_frame(
            responder, key, pn=pn, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END,
            payload=peer_tmp_box, bytes_sent=0,
        )
    )
    pn += 1
    assert responder.completed_tmp_boxes[PEER_MAC] == [peer_tmp_box]

    # Its completion clears the pending flag and fires our own queued send,
    # alongside the ACK for its own last packet.
    assert len(reply) == 2
    syn = ccmp.decrypt_data_frame(reply[1], key)
    syn_header, _ = sptcp.parse_packet(syn.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert syn_header.flags == sptcp.FLAG_SYN
    assert responder._sessions[PEER_MAC].pending_outgoing_payload == outbound_tmp_box
    assert responder._sessions[PEER_MAC].queued_send is None
    assert responder._sessions[PEER_MAC].tmp_box_download_pending is False


def _peer_probe_response(responder: StreetPassResponder, *, with_tag: bool = True, seq_ctrl: int = 0) -> bytes:
    """A Probe Response as if PEER_MAC is answering our own broadcast/second
    Probe Request -- addr1 (destination) is us, addr2/addr3 (source) is the
    peer."""
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,  # placeholder; build_probe_response fixes this
        duration=0,
        addr1=responder.identity.mac,
        addr2=PEER_MAC,
        addr3=PEER_MAC,
        seq_ctrl=seq_ctrl,
    )
    ies = [(dot11.SSID_IE_TAG, b"")]
    if with_tag:
        nintendo_tag = dot11.build_nintendo_tag([PEER_SERVICE], PEER_CONSOLE_ID)
        ies.append((dot11.VENDOR_SPECIFIC_IE_TAG, dot11.NINTENDO_OUI + bytes([dot11.NINTENDO_OUI_TYPE]) + nintendo_tag))
    return dot11.build_probe_response(header=header, ies=ies)


def test_build_broadcast_probe_carries_our_own_nintendo_tag():
    """ (2026-09-15): this project's first-ever
    self-initiated Probe Request -- every test before this only ever
    answered a peer's own broadcast."""
    responder = _responder()

    frame = responder.build_broadcast_probe()
    request = dot11.parse_probe_request(frame)

    assert request.header.addr1 == dot11.BROADCAST_MAC
    assert request.header.addr2 == responder.identity.mac
    assert request.ssid == dot11.STREETPASS_SSID.encode("ascii")
    tag = dot11.find_nintendo_tag(request.ies)
    assert tag is not None
    assert tag.console_id == responder.identity.console_id
    assert tag.services == [PEER_SERVICE]


def test_prober_answers_first_probe_response_with_action_frame_and_second_probe():
    """The prober side of 's captured
    sequence, roles reversed: our broadcast got answered, so we should
    reply with an Action frame *and* our own second (unicast) Probe
    Request -- this project had never sent either before."""
    responder = _responder()
    responder.build_broadcast_probe()  # no per-peer state touched yet

    reply = responder.handle_frame(_peer_probe_response(responder))

    assert len(reply) == 2
    action = dot11.parse_action_frame(reply[0])
    assert action.header.addr1 == PEER_MAC
    assert action.header.addr2 == responder.identity.mac

    second_probe = dot11.parse_probe_request(reply[1])
    assert second_probe.header.addr1 == PEER_MAC  # unicast, not broadcast
    assert second_probe.header.addr2 == responder.identity.mac
    assert second_probe.ssid == b""  # project findings: no SSID on the second request
    assert dot11.find_nintendo_tag(second_probe.ies) is None  # ...and no Nintendo tag either

    assert responder._sessions[PEER_MAC].prober_stage is ProberStage.GOT_FIRST_RESPONSE
    assert responder._sessions[PEER_MAC].console_id == PEER_CONSOLE_ID
    # PeerState (the responder-role tracker) is untouched at this stage.
    assert PEER_MAC not in responder.peers


def test_prober_ignores_a_first_probe_response_without_a_nintendo_tag():
    """ wild-capture bug (2026-09-16): an
    ordinary WiFi AP replying to our broadcast probe with its own mundane
    (non-3DS) Probe Response used to sail through with no tag check at
    all, advancing prober_stage on pure noise -- observed live on a Raspberry Pi
    (490-byte Probe Response from some nearby access point, addr1-matched
    to us since we'd just broadcast). A duplicate of that same frame then
    satisfied the *second*-response branch too, producing a bogus
    ESTABLISHED peer that never sent a byte of real StreetPass traffic."""
    responder = _responder()
    responder.build_broadcast_probe()

    reply = responder.handle_frame(_peer_probe_response(responder, with_tag=False))

    assert reply == []
    # _session_for() lazily creates an entry as a side effect of lookup,
    # but nothing should have actually advanced on it.
    assert responder._sessions[PEER_MAC].prober_stage is None
    assert PEER_MAC not in responder.peers


def test_prober_establishes_on_second_probe_response():
    responder = _responder()
    responder.handle_frame(_peer_probe_response(responder))  # -> GOT_FIRST_RESPONSE

    reply = responder.handle_frame(_peer_probe_response(responder, with_tag=False, seq_ctrl=16))

    assert reply == []
    assert responder._sessions[PEER_MAC].prober_stage is ProberStage.ESTABLISHED
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED


def test_prober_ignores_a_third_probe_response_once_established():
    responder = _responder()
    responder.handle_frame(_peer_probe_response(responder))
    responder.handle_frame(_peer_probe_response(responder, with_tag=False, seq_ctrl=16))

    reply = responder.handle_frame(_peer_probe_response(responder, with_tag=False, seq_ctrl=32))

    assert reply == []
    assert responder._sessions[PEER_MAC].prober_stage is ProberStage.ESTABLISHED


def test_prober_ignores_probe_response_not_addressed_to_us():
    responder = _responder()
    someone_else = bytes.fromhex("999999999999")
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST,
        duration=0,
        addr1=someone_else,
        addr2=PEER_MAC,
        addr3=PEER_MAC,
        seq_ctrl=0,
    )
    frame = dot11.build_probe_response(header=header, ies=[(dot11.SSID_IE_TAG, b"")])

    reply = responder.handle_frame(frame)

    assert reply == []
    assert PEER_MAC not in responder._sessions


def test_established_prober_peer_can_still_be_decrypted_as_a_data_frame_source():
    """Once ProberStage reaches ESTABLISHED, the existing (unchanged)
    _handle_data_frame() path should recognize this peer exactly like a
    responder-role one -- a real peer starts sending CCMP Data frames
    unprompted right after this point regardless of which side probed
    which, so this project's own reactive
    handling shouldn't need to know or care which role got it there."""
    responder = _responder()
    responder.keyslot_2e_key = _TEST_KEYSLOT_2E_KEY
    responder.handle_frame(_peer_probe_response(responder))
    responder.handle_frame(_peer_probe_response(responder, with_tag=False, seq_ctrl=16))
    assert responder.peers[PEER_MAC] is PeerState.ESTABLISHED

    key = crypto.derive_ccmp_key(
        crypto.build_hash_block(
            host_console_id=responder.identity.console_id,
            client_console_id=PEER_CONSOLE_ID,
            host_mac=responder.identity.mac,
            client_mac=PEER_MAC,
        ),
        responder.hmac_key,
        _TEST_KEYSLOT_2E_KEY,
    )
    syn = sptcp.MSDU_PREAMBLE + sptcp.build_handshake_packet(sptcp.FLAG_SYN)
    frame = ccmp.build_data_frame(
        dest=responder.identity.mac, src=PEER_MAC, bssid=PEER_MAC, seq_ctrl=0, pn=1, key=key, plaintext=syn,
    )

    reply = responder.handle_frame(frame)

    assert len(reply) == 1
    decrypted = ccmp.decrypt_data_frame(reply[0], key)
    header, _ = sptcp.parse_packet(decrypted.plaintext[len(sptcp.MSDU_PREAMBLE):])
    assert header.flags == (sptcp.FLAG_SYN | sptcp.FLAG_ACK)


ACNL_SERVICE = bytes.fromhex("00198d0030")  # Animal Crossing: New Leaf (title 0x00198D00)


def test_peer_message_boxes_lists_what_the_console_offers_and_extra_service_is_echoed():
    """`--extra-service`: a responder announcing the Animal Crossing service must ask for that title's message,
    and `peer_message_boxes()` must expose every box the console announced (including ones we do not want)."""
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    responder = StreetPassResponder(
        identity=identity, services=[PEER_SERVICE, ACNL_SERVICE], keyslot_2e_key=_TEST_KEYSLOT_2E_KEY
    )
    responder.handle_frame(_peer_broadcast_probe_request())
    assert responder.peer_message_boxes() == {}
    key = _expected_ccmp_key(responder)
    acnl_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00198D00, send_mode=0, flag=3, send_state=0, send_size=0x7DE8, message_count=1
    )
    other_entry = spmtp.MessageBoxMetadataEntry(
        title_id=0x00099999, send_mode=0, flag=3, send_state=0, send_size=100, message_count=1
    )
    peer_list_payload = spmtp.build_handshake_header(
        spmtp.HandshakeHeader(packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT, content_size=0x2C + 0x40)
    ) + spmtp.build_message_box_metadata_list([acnl_entry, other_entry])
    responder.handle_frame(_spmtp_data_frame(responder, key, pn=1, spmtp_payload=peer_list_payload))

    assert responder.peer_message_boxes() == {PEER_MAC: [acnl_entry, other_entry]}
    assert responder._wanted_title_ids() >= {0x00198D00, 0x00020800}
    assert 0x00099999 not in responder._wanted_title_ids()


def test_responder_collects_two_tmp_boxes_when_the_second_restarts_at_bytes_sent_zero(monkeypatch):
    """Live (2026-10-24): a console offering Mii Plaza and Animal Crossing sent the two boxes back to back, and the
    second box's bytes_sent started over at 0 (per box, not cumulative across the queue). The second box used to be
    discarded as stale data, so only Mii Plaza was ever received."""
    monkeypatch.setattr(session_module, "TMP_BOX_WINDOW_SIZE", 8)
    responder = _responder_with_ccmp()
    responder.handle_frame(_peer_broadcast_probe_request())
    key = _expected_ccmp_key(responder)

    def make_box(title_id: int, fill: int) -> bytes:
        body = bytes([fill]) * 20
        return spmtp.build_tmp_box_header(
            spmtp.TmpBoxHeader(size=spmtp.TMP_BOX_HEADER_SIZE + len(body), title_id=title_id, group_id=0, message_count=1)
        ) + body

    boxes = [make_box(0x00020800, 0x11), make_box(0x00198D00, 0x22)]
    pn = 1
    for box in boxes:
        for start in range(0, len(box), 8):
            window = box[start:start + 8]
            responder.handle_frame(
                _tmp_box_data_frame(responder, key, pn=pn, flags=sptcp.FLAG_ACK, payload=window[:4], bytes_sent=start)
            )
            responder.handle_frame(
                _tmp_box_data_frame(
                    responder, key, pn=pn + 1, flags=sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END,
                    payload=window[4:], bytes_sent=start + 4,
                )
            )
            pn += 2

    assert responder.completed_tmp_boxes[PEER_MAC] == boxes
