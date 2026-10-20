import hashlib
import hmac
import struct

import pytest

from streetpass_emu import icon, tmp_box_builder as tb
from streetpass_emu.mii_qr import verify_mii_blob_tag
from streetpass_emu.smdh import Title


def fake_mii() -> bytes:
    m = bytearray(range(96))
    return bytes(m)


def build(**kw):
    return tb.build_message(tb.BoxSpec(mii=fake_mii(), **kw))


def test_sizes_match_genuine_boxes():
    msg = build()
    magic, _p, msize, hsize, bsize = struct.unpack_from("<HHIII", msg, 0)
    assert (magic, msize, hsize, bsize) == (0x6060, 32692, 0xD14, 0x7280)
    assert len(msg) == msize


def test_trailer_is_hmac_of_body_only():
    msg = build(comment="こんにちは")
    body = msg[0xD14:0xD14 + 0x7280]
    assert msg[-32:] == hmac.new(tb.MII_PLAZA_HMAC_KEY, body, hashlib.sha256).digest()


def test_sender_mii_blob_has_valid_ccm_tag():
    msg = build()
    assert verify_mii_blob_tag(msg[0xD14 + tb.OFF_MII:0xD14 + tb.OFF_MII + 112])


def test_header_fields():
    msg = build(message_id=bytes(range(8)))
    assert struct.unpack_from("<I", msg, 0x10)[0] == 0x20800
    assert msg[0x20:0x28] == bytes(range(8))
    assert (msg[0x34], msg[0x6C], msg[0x6D]) == (3, 0xFF, 1)
    # TLV id=2 (3200 B icon) then id=4 (18 B text)
    assert struct.unpack_from("<II", msg, 0x70) == (2, 3200)
    assert struct.unpack_from("<II", msg, 0x70 + 8 + 3200) == (4, 18)


def test_spec_roundtrip():
    spec = tb.BoxSpec(
        mii=fake_mii(), comment="あいうえお", notice="来たよ",
        header_icon=icon.solid(icon.TLV_SIZE, (10, 200, 30)),
        titles=[Title("名前", "long", "pub")],
        small_icon=icon.solid(icon.SMALL_SIZE, (255, 0, 0)),
        large_icon=icon.solid(icon.LARGE_SIZE, (0, 0, 255)),
        country=1, region=41, country_names=["日本", "Japan"], region_names=["福岡県"],
        visit_counter=77, message_id=b"12345678",
    )
    back = tb.spec_from_message(tb.build_message(spec))
    assert back.comment == "あいうえお" and back.notice == "来たよ"
    assert back.header_icon == spec.header_icon
    assert back.small_icon == spec.small_icon and back.large_icon == spec.large_icon
    assert (back.country, back.region, back.visit_counter) == (1, 41, 77)
    assert back.titles[0] == Title("名前", "long", "pub") and back.titles[15] == back.titles[0]
    assert back.country_names[0] == "日本" and back.country_names[15] == "Japan"
    assert back.message_id == b"12345678"
    assert back.mii[:12] == spec.mii[:12]  # checksum bytes are recomputed


def test_mii_id_copy_and_residence_words():
    msg = build(country=1, region=41)
    body = msg[0xD14:]
    assert body[tb.OFF_MII_ID_COPY:tb.OFF_MII_ID_COPY + 10] == fake_mii()[12:22]
    assert body[tb.OFF_RESIDENCE:tb.OFF_RESIDENCE + 4] == bytes([0, 0, 41, 1])


def test_comment_limit():
    build(comment="1234567890123456")
    with pytest.raises(ValueError):
        build(comment="12345678901234567")


def test_bad_inputs():
    with pytest.raises(ValueError):
        tb.build_message(tb.BoxSpec(mii=bytes(10)))
    with pytest.raises(ValueError):
        build(header_icon=bytes(5))
    with pytest.raises(ValueError):
        build(notice="x" * 9)


def test_mii_from_blob_or_raw():
    raw = fake_mii()
    assert tb.mii_from_blob_or_raw(raw) == raw
    from streetpass_emu.mii_qr import encode_mii_blob
    decoded = tb.mii_from_blob_or_raw(encode_mii_blob(raw))
    assert decoded[:12] == raw[:12] and decoded[12:94] == raw[12:94]
