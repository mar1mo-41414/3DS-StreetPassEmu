import json

import pytest

from streetpass_emu import friend_code, keyslot_2e
from streetpass_emu.spmtp import principal_id_checksum


def test_json_files_are_read_as_utf8_whatever_the_locale(tmp_path, monkeypatch):
    """Windows opens text files as cp932 by default; a file with Japanese text must still load."""
    import locale

    pid = 305419896
    code = f"{(principal_id_checksum(pid) << 32) | pid:012d}"
    f = tmp_path / "friend_code.json"
    f.write_text(json.dumps({"friend_code": code, "note": "メモ: テスト"}, ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(locale, "getpreferredencoding", lambda *a, **k: "cp932")
    assert friend_code.load_friend_code(str(f)) == int(code)

    k = tmp_path / "key.json"
    k.write_text(json.dumps({"key_x": "00" * 16, "key_y": "11" * 16, "note": "鍵"}, ensure_ascii=False), encoding="utf-8")
    assert len(keyslot_2e.load_streetpass_normal_key(str(k))) == 16
