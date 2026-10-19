import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from streetpass_emu import mii  # noqa: E402
from streetpass_emu.mii_qr import crc16_xmodem  # noqa: E402

import extract_console_miis as ecm  # noqa: E402


def _sample_official(name: str, author_id: int, device_hash: bytes) -> mii.MiiOfficial:
    """A synthetic (not-real-person) MiiOfficial for testing -- see
    tests/test_mii.py's own note on avoiding real Mii data in fixtures."""
    core = mii.MiiCore(
        birth_platform=2, font_region=0, region_move=0, copyable=True, mii_version=3,
        author_id=author_id, mii_id=mii.CreateID(flags=8, timestamp=123456, device_hash=device_hash),
        favorite_color=5, birth_month=4, birth_day=14, gender=0, mii_name=name,
        height=64, build=64, blush_type=1, face_style=2, face_color=3, face_type=4, local_only=False,
        hair_mirrored=0, hair_color=5, hair_type=10,
        eye_thickness=1, eye_scale=2, eye_color=3, eye_type=20, eye_height=10, eye_distance=5, eye_rotation=4,
        eyebrow_thickness=1, eyebrow_scale=2, eyebrow_color=3, eyebrow_type=10, eyebrow_height=10,
        eyebrow_distance=5, eyebrow_rotation=4,
        nose_height=10, nose_scale=5, nose_type=8, mouth_thickness=1, mouth_scale=2, mouth_color=3, mouth_type=15,
        mustache_type=1, mouth_height=5, mustache_height=10, mustache_scale=3, beard_color=2, beard_type=1,
        glass_height=5, glass_scale=3, glass_color=2, glass_type=4,
        mole_ypos=10, mole_xpos=5, mole_scale=3, mole_enabled=True,
    )
    return mii.MiiOfficial(core=core, creator_name=name)


def _empty_slot_filler() -> bytes:
    """CFL_DB's real fill pattern for unused slots (0xff 0x7f repeating) -- must NOT be picked up as a real Mii."""
    return (b"\xff\x7f") * (mii.OFFICIAL_SIZE // 2)


def _build_fake_cfl_db(officials: list[mii.MiiOfficial]) -> bytes:
    header = b"\x00" * ecm.HEADER_SIZE
    body = b"".join(mii.build_mii_official(o) for o in officials)
    # a couple of trailing empty slots, like a real (mostly-unused) CFL_DB
    body += _empty_slot_filler() * 2
    return header + body


def test_find_miis_skips_empty_slots_and_finds_real_ones():
    real = [
        _sample_official("Alice", 0x1111111111111111, b"\x01\x02\x03\x04\x05\x06"),
        _sample_official("Bob", 0x2222222222222222, b"\x0a\x0b\x0c\x0d\x0e\x0f"),
    ]
    cfl_db = _build_fake_cfl_db(real)

    found = ecm.find_miis(cfl_db)

    assert [m.core.mii_name for _offset, m in found] == ["Alice", "Bob"]


def test_to_ffl_store_data_produces_a_valid_checksum():
    official = _sample_official("Carol", 0x3333333333333333, b"\x10\x20\x30\x40\x50\x60")
    raw_92 = mii.build_mii_official(official)

    ffl = ecm.to_ffl_store_data(raw_92)

    assert len(ffl) == ecm.FFL_STORE_DATA_SIZE
    assert ffl[:92] == raw_92
    assert ffl[92:94] == b"\x00\x00"
    expected_crc = crc16_xmodem(ffl[:94])
    assert struct.unpack(">H", ffl[94:96])[0] == expected_crc


def test_to_ffl_store_data_rejects_wrong_size():
    with pytest.raises(ValueError):
        ecm.to_ffl_store_data(b"\x00" * 10)


def test_extract_cli_writes_the_selected_entry(tmp_path):
    real = [_sample_official("Dave", 0x4444444444444444, b"\xaa\xbb\xcc\xdd\xee\xff")]
    cfl_db_path = tmp_path / "cfl_db.dat"
    cfl_db_path.write_bytes(_build_fake_cfl_db(real))
    out_path = tmp_path / "out.bin"

    args = ecm.argparse.Namespace(cfl_db=cfl_db_path, index=0, output=out_path)
    rc = ecm.cmd_extract(args)

    assert rc == 0
    ffl = out_path.read_bytes()
    assert len(ffl) == ecm.FFL_STORE_DATA_SIZE
    assert mii.parse_mii_official(ffl[:92]).core.mii_name == "Dave"
