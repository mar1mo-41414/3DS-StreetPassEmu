"""Loads a real Nintendo friend code from a local file the caller supplies,
rather than embedding it in source.

Unlike keyslot 0x2E's key (keyslot_2e.py), a friend code isn't secret in the
"breaks the crypto" sense -- it's kept out of this repository because it's
personally identifying: unlike a StreetPass session's rotating MAC/consoleID,
a friend code lets anyone, anywhere (not just someone physically nearby) add
the console to their friend list on Nintendo Network. Point
STREETPASS_FRIEND_CODE_FILE at a local JSON file with a "friend_code" string
(e.g. "4126-2228-0312") to use one instead of the default of not having a
real one at all (project findings answers with an honest 0/"not a
friend" when nothing is configured).
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .spmtp import friend_code_value_from_string

DEFAULT_ENV_VAR = "STREETPASS_FRIEND_CODE_FILE"


class FriendCodeFileNotFound(FileNotFoundError):
    """No friend code file was found (see this module's docstring)."""


def load_friend_code(path: Optional[str] = None) -> int:
    """Read a local JSON file with a `friend_code` string (e.g.
    "4126-2228-0312") and return the raw 64-bit value FriendCodePacket
    expects (spmtp.friend_code_value_from_string()).

    Args:
        path: explicit file path. If omitted, reads the
            STREETPASS_FRIEND_CODE_FILE environment variable instead.
    """
    resolved = path or os.environ.get(DEFAULT_ENV_VAR)
    if not resolved:
        raise FriendCodeFileNotFound(
            f"no friend code file given and {DEFAULT_ENV_VAR} is not set "
            " -- pass path= explicitly or set the env var"
        )
    with open(resolved) as f:
        data = json.load(f)
    return friend_code_value_from_string(data["friend_code"])
