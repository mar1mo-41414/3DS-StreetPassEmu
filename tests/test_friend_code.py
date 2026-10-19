import json

import pytest

from streetpass_emu.friend_code import DEFAULT_ENV_VAR, FriendCodeFileNotFound, load_friend_code
from streetpass_emu.spmtp import friend_code_value_from_string

# A friend code whose checksum genuinely validates -- computed the same way
# real hardware would, not an arbitrary placeholder (see
# test_spmtp.py::test_friend_code_value_from_string_matches_a_known_valid_code
# for a value cross-checked another way).
_VALID_FRIEND_CODE = "4126-2228-0312"


def test_load_from_explicit_path(tmp_path):
    friend_code_file = tmp_path / "friend_code.json"
    friend_code_file.write_text(json.dumps({"friend_code": _VALID_FRIEND_CODE}))

    result = load_friend_code(str(friend_code_file))

    assert result == friend_code_value_from_string(_VALID_FRIEND_CODE)


def test_load_from_env_var(tmp_path, monkeypatch):
    friend_code_file = tmp_path / "friend_code.json"
    friend_code_file.write_text(json.dumps({"friend_code": _VALID_FRIEND_CODE}))
    monkeypatch.setenv(DEFAULT_ENV_VAR, str(friend_code_file))

    result = load_friend_code()

    assert result == friend_code_value_from_string(_VALID_FRIEND_CODE)


def test_raises_clear_error_when_no_path_or_env_var(monkeypatch):
    monkeypatch.delenv(DEFAULT_ENV_VAR, raising=False)

    with pytest.raises(FriendCodeFileNotFound):
        load_friend_code()
