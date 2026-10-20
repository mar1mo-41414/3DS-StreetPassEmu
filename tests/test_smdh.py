import pytest

from streetpass_emu.smdh import (
    LONG_DESCRIPTION_SIZE,
    PUBLISHER_SIZE,
    SHORT_DESCRIPTION_SIZE,
    TITLE_COUNT,
    TITLE_ENTRY_SIZE,
    TITLE_TABLE_SIZE,
    Title,
    build_title,
    build_title_table,
    parse_title,
    parse_title_table,
)


def _padded_utf16(text: str, size: int) -> bytes:
    return text.encode("utf-16-le").ljust(size, b"\0")


# Real captured title entry: console A's own "FBI" homebrew banner, found
# embedded in a real live StreetPass TMP Box transfer (project findings
# §7.25) and independently confirmed present in console A's own NAND icon
# cache.
_FBI_ENTRY = (
    _padded_utf16("FBI", SHORT_DESCRIPTION_SIZE)
    + _padded_utf16("FBI - Open source title manager.", LONG_DESCRIPTION_SIZE)
    + _padded_utf16("Steveice10", PUBLISHER_SIZE)
)

# Real captured title entry: a retail game's banner ("New SUPER MARIO
# BROS. 2" / Nintendo) found in console B's own NAND icon cache (docs/
# PROTOCOL.md §7.28) -- confirms the same structure holds for a real
# eShop/retail title, not just homebrew.
_MARIO_ENTRY = (
    _padded_utf16("New SUPER MARIO BROS.", SHORT_DESCRIPTION_SIZE)
    + _padded_utf16("New SUPER MARIO BROS. 2", LONG_DESCRIPTION_SIZE)
    + _padded_utf16("Nintendo", PUBLISHER_SIZE)
)


def test_title_entry_size_matches_real_captures():
    assert len(_FBI_ENTRY) == TITLE_ENTRY_SIZE == 0x200
    assert len(_MARIO_ENTRY) == TITLE_ENTRY_SIZE


def test_parse_title_matches_real_fbi_capture():
    assert parse_title(_FBI_ENTRY) == Title(
        short_description="FBI", long_description="FBI - Open source title manager.", publisher="Steveice10",
    )


def test_parse_title_matches_real_retail_game_capture():
    assert parse_title(_MARIO_ENTRY) == Title(
        short_description="New SUPER MARIO BROS.", long_description="New SUPER MARIO BROS. 2", publisher="Nintendo",
    )


def test_build_title_round_trips():
    title = Title(short_description="Test", long_description="Test Game Long Title", publisher="Test Co.")
    assert parse_title(build_title(title)) == title


def test_build_title_rejects_text_too_long_to_fit():
    with pytest.raises(ValueError):
        build_title(Title(short_description="x" * 100, long_description="ok", publisher="ok"))


def test_title_table_size_matches_real_capture():
    """project findings: a real Title[16] array spanned exactly 8192
    bytes (16 * 512)."""
    assert TITLE_TABLE_SIZE == 0x2000
    assert TITLE_TABLE_SIZE == TITLE_ENTRY_SIZE * TITLE_COUNT


def test_parse_title_table_matches_real_capture_of_16_identical_entries():
    """project findings: every real capture so far had the exact same
    text repeated in all 16 language slots."""
    data = _FBI_ENTRY * 16
    titles = parse_title_table(data)
    assert len(titles) == 16
    assert all(t == Title("FBI", "FBI - Open source title manager.", "Steveice10") for t in titles)


def test_build_title_table_repeats_a_single_title_to_fill_16_slots():
    table = build_title_table([Title("FBI", "FBI - Open source title manager.", "Steveice10")])
    assert len(table) == TITLE_TABLE_SIZE
    assert table == _FBI_ENTRY * 16


def test_build_title_table_rejects_more_than_16():
    with pytest.raises(ValueError):
        build_title_table([Title("a", "a", "a")] * 17)


def test_build_title_table_rejects_empty():
    with pytest.raises(ValueError):
        build_title_table([])


def test_parse_smdh_reads_titles_and_icons():
    from streetpass_emu.smdh import SMDH_SIZE, Title, build_title_table, parse_smdh
    data = bytearray(SMDH_SIZE)
    data[:4] = b"SMDH"
    data[8:8 + 0x2000] = build_title_table([Title("名", "long", "pub")])
    data[0x2040:0x2040 + 0x480] = b"\x11" * 0x480
    data[0x24C0:0x24C0 + 0x1200] = b"\x22" * 0x1200
    s = parse_smdh(bytes(data))
    assert s.titles[0] == Title("名", "long", "pub") and len(s.titles) == 16
    assert s.small_icon == b"\x11" * 0x480 and s.large_icon == b"\x22" * 0x1200
    with pytest.raises(ValueError):
        parse_smdh(bytes(SMDH_SIZE))
