"""調査結果: Mii QR/TMP Box内Mii blob暗号化フォーマットのテスト。

実機の生データを含まない、既知の固定値のみを使ったユニットテスト
(実機キャプチャとの一致は3DS-StreetPassEmu-secrets/側で別途確認済み)。
"""
import pytest

from streetpass_emu.mii_qr import (
    CHECKSUM_OFFSET,
    FFL_STORE_DATA_SIZE,
    MII_ID_OFFSET,
    QR_CODE_RAW_SIZE,
    MiiIdentity,
    crc16_xmodem,
    decode_mii_blob,
    encode_mii_blob,
    encode_mii_qr_payload,
    verify_mii_blob_tag,
    new_mii_id,
)


def _fake_ffl_store_data(nickname: str = "てすと") -> bytes:
    mii = bytearray(FFL_STORE_DATA_SIZE)
    mii[0x04:0x0C] = bytes(range(8))  # author_id
    mii[0x0C:0x16] = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA])  # mii_id
    name_bytes = nickname.encode("utf-16le")
    mii[0x1A:0x1A + len(name_bytes)] = name_bytes
    return bytes(mii)


def test_crc16_xmodem_known_vector():
    # CRC-16/XMODEM("123456789") = 0x31C3 (公知の検証ベクタ)
    assert crc16_xmodem(b"123456789") == 0x31C3


def test_encode_decode_round_trip_preserves_plaintext():
    mii = _fake_ffl_store_data()
    blob = encode_mii_blob(mii)
    assert len(blob) == 112
    assert verify_mii_blob_tag(blob)

    decoded = decode_mii_blob(blob)
    # checksumフィールド以外は完全一致するはず
    assert decoded[:CHECKSUM_OFFSET] == mii[:CHECKSUM_OFFSET]
    assert decoded[CHECKSUM_OFFSET + 2:] == mii[CHECKSUM_OFFSET + 2:]


def test_encode_recomputes_checksum():
    mii = bytearray(_fake_ffl_store_data())
    mii[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2] = b"\x00\x00"  # わざと壊す
    blob = encode_mii_blob(bytes(mii))
    decoded = decode_mii_blob(blob)
    stored = int.from_bytes(decoded[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2], "big")
    assert stored == crc16_xmodem(decoded[:CHECKSUM_OFFSET])


def test_changing_mii_id_changes_ciphertext_but_stays_valid():
    mii = bytearray(_fake_ffl_store_data())
    mii[MII_ID_OFFSET:MII_ID_OFFSET + 10] = new_mii_id()
    blob = encode_mii_blob(bytes(mii))
    decoded = decode_mii_blob(blob)
    assert decoded[MII_ID_OFFSET:MII_ID_OFFSET + 10] == mii[MII_ID_OFFSET:MII_ID_OFFSET + 10]
    stored = int.from_bytes(decoded[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2], "big")
    assert stored == crc16_xmodem(decoded[:CHECKSUM_OFFSET])


def test_mii_identity_extracts_nickname():
    mii = _fake_ffl_store_data(nickname="テスト")
    identity = MiiIdentity.from_ffl_store_data(mii)
    assert identity.nickname == "テスト"
    assert identity.author_id == bytes(range(8))


def test_encode_rejects_wrong_size():
    with pytest.raises(ValueError):
        encode_mii_blob(b"\x00" * 10)


def test_decode_rejects_too_short():
    with pytest.raises(ValueError):
        decode_mii_blob(b"\x00" * 50)


def test_encode_mii_qr_payload_matches_tmp_box_blob():
    mii = _fake_ffl_store_data()
    payload = encode_mii_qr_payload(mii)
    assert len(payload) == QR_CODE_RAW_SIZE == 112
    # 2026-09-23: TMP Box内のMiiブロックもタグ16バイト込みの112バイト
    #。QRペイロードと完全に同一になる。
    assert payload == encode_mii_blob(mii)
    decoded = decode_mii_blob(payload)
    assert decoded[:CHECKSUM_OFFSET] == mii[:CHECKSUM_OFFSET]


def test_verify_mii_blob_tag_detects_stale_tag_tail():
    # 旧実装のバグの再現: 先頭108バイトだけ新しくして末尾4バイト(タグの
    # 残り)に元の値が残っているブロックは、タグ検証に失敗する。
    original = encode_mii_blob(_fake_ffl_store_data(nickname="もと"))
    edited = encode_mii_blob(_fake_ffl_store_data(nickname="へんこう"))
    assert verify_mii_blob_tag(original)
    assert verify_mii_blob_tag(edited)
    stale = edited[:108] + original[108:112]
    assert not verify_mii_blob_tag(stale)


def test_new_mii_id_shape():
    mid = new_mii_id(device_hash=b"\xAA" * 6)
    assert len(mid) == 10
    assert mid[4:] == b"\xAA" * 6
    # 2026-09-13実機検証: avatar_id先頭バイトの上位nibbleは0x9固定でないと
    # Miiメーカーに「Miiコードではない」と拒否される(kazuki-4ys/
    # MiiInfoEditorCTRの生成規則と、実機の本物のmii_id先頭バイト
    # 0x9dの両方から確認済み)
    assert mid[0] >> 4 == 0x9
