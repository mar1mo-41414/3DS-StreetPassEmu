import json

import pytest

from streetpass_emu.keyscrambler import keygen_manual
from streetpass_emu.keyslot_2e import DEFAULT_ENV_VAR, KeyslotFileNotFound, load_streetpass_normal_key

# Arbitrary, non-secret placeholder key material -- exercises the file
# loading/parsing path only, not any real device's keyslot 0x2E.
_KEY_X = "000102030405060708090a0b0c0d0e0f"
_KEY_Y = "f0e0d0c0b0a090807060504030201000"[:32]


def test_load_from_explicit_path(tmp_path):
    key_file = tmp_path / "keyslot_2e.json"
    key_file.write_text(json.dumps({"key_x": _KEY_X, "key_y": _KEY_Y}))

    result = load_streetpass_normal_key(str(key_file))

    assert result == keygen_manual(bytes.fromhex(_KEY_X), bytes.fromhex(_KEY_Y))


def test_load_from_env_var(tmp_path, monkeypatch):
    key_file = tmp_path / "keyslot_2e.json"
    key_file.write_text(json.dumps({"key_x": _KEY_X, "key_y": _KEY_Y}))
    monkeypatch.setenv(DEFAULT_ENV_VAR, str(key_file))

    result = load_streetpass_normal_key()

    assert result == keygen_manual(bytes.fromhex(_KEY_X), bytes.fromhex(_KEY_Y))


def test_raises_clear_error_when_no_path_or_env_var(monkeypatch):
    monkeypatch.delenv(DEFAULT_ENV_VAR, raising=False)

    with pytest.raises(KeyslotFileNotFound):
        load_streetpass_normal_key()
