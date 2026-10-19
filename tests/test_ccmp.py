import pytest

from streetpass_emu import ccmp, dot11

# Arbitrary, non-secret key -- exercises the framing/AAD/nonce logic only,
# not any real device's keyslot 0x2E.
KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
US_MAC = bytes.fromhex("222222222222")
PEER_MAC = bytes.fromhex("da6bf722f377")  # same placeholder used in test_session.py


def test_round_trips_through_build_and_decrypt():
    plaintext = b"\x59\x59\x30\x00" + bytes(20)  # SPTCP-shaped, but content doesn't matter here

    frame = ccmp.build_data_frame(
        dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=1, key=KEY, plaintext=plaintext,
    )
    result = ccmp.decrypt_data_frame(frame, KEY)

    assert result.plaintext == plaintext
    assert result.pn == 1
    assert result.src == US_MAC
    assert result.dest == PEER_MAC


def test_built_frame_has_the_real_protected_data_frame_control():
    frame = ccmp.build_data_frame(dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=1, key=KEY, plaintext=b"x")
    header = dot11.parse_management_header(frame)
    assert header.frame_control == dot11.FC_DATA_PROTECTED


def test_pn_round_trips_for_large_values():
    frame = ccmp.build_data_frame(dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=0xFFEEDDCCBBAA, key=KEY, plaintext=b"hi")
    result = ccmp.decrypt_data_frame(frame, KEY)
    assert result.pn == 0xFFEEDDCCBBAA


def test_wrong_key_fails_mic_verification():
    frame = ccmp.build_data_frame(dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=1, key=KEY, plaintext=b"secret")
    wrong_key = bytes(16)

    with pytest.raises(ccmp.CcmpError):
        ccmp.decrypt_data_frame(frame, wrong_key)


def test_tampered_ciphertext_fails_mic_verification():
    frame = bytearray(ccmp.build_data_frame(dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=1, key=KEY, plaintext=b"secret"))
    frame[-1] ^= 0xFF  # flip a bit inside the MIC

    with pytest.raises(ccmp.CcmpError):
        ccmp.decrypt_data_frame(bytes(frame), KEY)


def test_retry_bit_does_not_break_mic_verification():
    """project findings: a real retried frame's MIC only matched once
    Retry/PwrMgmt/MoreData were masked out of the AAD -- verify a frame we
    build ourselves with the Retry bit set still decrypts (matching what a
    real receiver's AAD construction must also do for retransmissions)."""
    frame = bytearray(ccmp.build_data_frame(dest=PEER_MAC, src=US_MAC, bssid=US_MAC, seq_ctrl=0, pn=1, key=KEY, plaintext=b"secret"))
    frame[1] |= 0x08  # set the Retry bit (high FC octet, bit 3) after the fact

    result = ccmp.decrypt_data_frame(bytes(frame), KEY)

    assert result.plaintext == b"secret"


def test_decrypt_rejects_non_data_frame():
    header = dot11.ManagementFrameHeader(
        frame_control=dot11.FC_PROBE_REQUEST, duration=0, addr1=PEER_MAC, addr2=US_MAC, addr3=US_MAC, seq_ctrl=0,
    )
    frame = dot11.build_management_header(header) + bytes(20)

    with pytest.raises(ccmp.CcmpError):
        ccmp.decrypt_data_frame(frame, KEY)


def test_decrypt_rejects_unprotected_data_frame():
    header = dot11.ManagementFrameHeader(
        frame_control=0x0008,  # Data, Protected bit NOT set
        duration=0, addr1=PEER_MAC, addr2=US_MAC, addr3=US_MAC, seq_ctrl=0,
    )
    frame = dot11.build_management_header(header) + bytes(20)

    with pytest.raises(ccmp.CcmpError):
        ccmp.decrypt_data_frame(frame, KEY)
