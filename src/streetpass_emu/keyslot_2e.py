"""Loads keyslot 0x2E's ("StreetPass") normal key from a local file the
caller supplies, rather than embedding it in source.

Unlike HMAC_KEY_RETAIL_CANDIDATE (crypto.py), keyslot 0x2E's raw KeyX/KeyY
are kept out of this repository on purpose even though they're a
firmware-wide constant -- they're the one piece
of material that, by itself, lets anyone compute real StreetPass CCMP
session keys offline with no hardware at all, which is a meaningfully
bigger step than the HMAC key alone. Extract your own with GodMode9's
AES key dumper (or equivalent) and point STREETPASS_KEYSLOT_2E_FILE at the
result --  the exact provenance and the
verification this project ran against real captured traffic.

If you don't have that file, use oracle.py instead: it gets the same
answer from a real console over the network, one CTR at a time, without
ever needing the raw key bytes on the PC side.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .keyscrambler import keygen_manual

DEFAULT_ENV_VAR = "STREETPASS_KEYSLOT_2E_FILE"


class KeyslotFileNotFound(FileNotFoundError):
    """No keyslot 0x2E key file was found (see this module's docstring)."""


def load_streetpass_normal_key(path: Optional[str] = None) -> bytes:
    """Read a local JSON file with `key_x`/`key_y` (hex strings, 16 bytes
    each) for AES keyslot 0x2E and return its normal key.

    Args:
        path: explicit file path. If omitted, reads the
            STREETPASS_KEYSLOT_2E_FILE environment variable instead.
    """
    resolved = path or os.environ.get(DEFAULT_ENV_VAR)
    if not resolved:
        raise KeyslotFileNotFound(
            f"no keyslot 0x2E key file given and {DEFAULT_ENV_VAR} is not set "
            " -- pass path= explicitly, set the env "
            "var, or use oracle.AesOracleClient instead if you don't have one"
        )
    with open(resolved, encoding="utf-8") as f:
        data = json.load(f)
    key_x = bytes.fromhex(data["key_x"])
    key_y = bytes.fromhex(data["key_y"])
    return keygen_manual(key_x, key_y)
