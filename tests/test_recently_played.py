import json

import pytest

from streetpass_emu import smdh
from streetpass_emu.recently_played import (
    DEFAULT_ENV_VAR,
    ENTRY_HEADER,
    RecentlyPlayedFileNotFound,
    RecentlyPlayedTitle,
    build_entry,
    build_recently_played_list,
    load_recently_played,
)

_FBI_TITLE = smdh.Title(short_description="FBI", long_description="FBI - Open source title manager.", publisher="Steveice10")


def test_build_entry_starts_with_the_confirmed_zero_header():
    """project findings: a real capture showed 8 zero bytes
    immediately before each entry's Title table."""
    entry = build_entry(RecentlyPlayedTitle(title=_FBI_TITLE))
    assert entry[:8] == ENTRY_HEADER == bytes(8)
    assert entry[8:8 + smdh.TITLE_TABLE_SIZE] == smdh.build_title_table([_FBI_TITLE])


def test_build_entry_appends_icon_bytes_verbatim():
    entry = build_entry(RecentlyPlayedTitle(title=_FBI_TITLE, icon=b"\x01\x02\x03"))
    assert entry.endswith(b"\x01\x02\x03")


def test_build_recently_played_list_concatenates_entries():
    entries = [RecentlyPlayedTitle(title=_FBI_TITLE), RecentlyPlayedTitle(title=_FBI_TITLE, icon=b"\xff")]
    result = build_recently_played_list(entries)
    assert result == build_entry(entries[0]) + build_entry(entries[1])


def test_load_recently_played_from_explicit_path(tmp_path):
    config_file = tmp_path / "recently_played.json"
    config_file.write_text(json.dumps({
        "entries": [{"short_title": "FBI", "long_title": "FBI - Open source title manager.", "publisher": "Steveice10"}]
    }))

    result = load_recently_played(str(config_file))

    assert result == [RecentlyPlayedTitle(title=_FBI_TITLE)]


def test_load_recently_played_with_icon_file(tmp_path):
    icon_file = tmp_path / "icon.bin"
    icon_file.write_bytes(b"\xaa\xbb")
    config_file = tmp_path / "recently_played.json"
    config_file.write_text(json.dumps({
        "entries": [{
            "short_title": "FBI", "long_title": "FBI - Open source title manager.", "publisher": "Steveice10",
            "icon_file": str(icon_file),
        }]
    }))

    result = load_recently_played(str(config_file))

    assert result == [RecentlyPlayedTitle(title=_FBI_TITLE, icon=b"\xaa\xbb")]


def test_load_recently_played_from_env_var(tmp_path, monkeypatch):
    config_file = tmp_path / "recently_played.json"
    config_file.write_text(json.dumps({
        "entries": [{"short_title": "FBI", "long_title": "FBI - Open source title manager.", "publisher": "Steveice10"}]
    }))
    monkeypatch.setenv(DEFAULT_ENV_VAR, str(config_file))

    result = load_recently_played()

    assert result == [RecentlyPlayedTitle(title=_FBI_TITLE)]


def test_raises_clear_error_when_no_path_or_env_var(monkeypatch):
    monkeypatch.delenv(DEFAULT_ENV_VAR, raising=False)

    with pytest.raises(RecentlyPlayedFileNotFound):
        load_recently_played()
