import pytest

from streetpass_emu import mii


def _sample_core(**overrides) -> mii.MiiCore:
    defaults = dict(
        birth_platform=2, font_region=0, region_move=0, copyable=True, mii_version=3,
        author_id=0x1122334455667788, mii_id=mii.CreateID(flags=8, timestamp=123456, device_hash=b"\x01\x02\x03\x04\x05\x06"),
        favorite_color=5, birth_month=4, birth_day=14, gender=0, mii_name="Test",
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
    defaults.update(overrides)
    return mii.MiiCore(**defaults)


def test_create_id_round_trips():
    create_id = mii.CreateID(flags=0xA, timestamp=0x0ABCDEF, device_hash=b"\xaa\xbb\xcc\xdd\xee\xff")
    assert mii.parse_create_id(mii.build_create_id(create_id)) == create_id


def test_create_id_rejects_wrong_size():
    with pytest.raises(ValueError):
        mii.parse_create_id(b"\x00" * 5)


def test_mii_core_round_trips_every_named_field():
    core = _sample_core()
    rebuilt = mii.parse_mii_core(mii.build_mii_core(core))
    assert rebuilt == core


def test_mii_core_rejects_wrong_size():
    with pytest.raises(ValueError):
        mii.parse_mii_core(b"\x00" * (mii.CORE_SIZE - 1))


def test_mii_official_round_trips():
    official = mii.MiiOfficial(core=_sample_core(), creator_name="Author")
    assert mii.parse_mii_official(mii.build_mii_official(official)) == official


def test_birthday_gender_favorite_color_bit_packing_matches_a_real_capture():
    """project findings: a real 3DS's own Mii database (CFL_DB) had
    this exact 2-byte value at its Mii record's birthday/gender/favorite
    color field, and decoding it here produces the console owner's actual
    real Mii birthday (April 14) and gender (male) -- confirming this
    module's MSB-first bit order (the opposite of a naive reading of the
    public C header, which gives an invalid month) against ground truth,
    not just an internally-consistent round trip."""
    real_capture_value = 0x69C8
    _u0, _u1, favorite_color, birth_day, birth_month, gender = mii._split_bits_msb_first(
        real_capture_value, [1, 1, 4, 5, 4, 1]
    )
    assert birth_month == 4
    assert birth_day == 14
    assert gender == 0  # male


def test_hair_mirrored_is_not_a_boolean():
    """project findings: despite its name suggesting a 1-bit flip
    flag, the C header declares this field 5 bits wide -- a real capture's
    value there didn't fit in 1 bit, confirming it has to stay a plain
    int, not bool()-coerced (which would silently discard information)."""
    core = _sample_core(hair_mirrored=17)
    rebuilt = mii.parse_mii_core(mii.build_mii_core(core))
    assert rebuilt.hair_mirrored == 17
