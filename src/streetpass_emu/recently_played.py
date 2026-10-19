"""Mii Plaza's "recently played software" StreetPass list.

Confirmed live to be a sequence of entries,
each an 8-byte zero header followed by a verbatim copy of that title's SMDH
Title[16] array (smdh.py) and then icon bitmap data. The icon's exact
internal layout isn't independently confirmed yet -- only that it starts
right after the Title table -- so entries here carry whatever icon bytes
you give them, unexamined. A real console, per two independent captures,
repeats the *same* entry (or a small number of them) back-to-back; this
project has not confirmed what determines how many entries a real console
sends, so build_recently_played_list() just concatenates whatever you pass
it.

This module is about *authoring* a custom list to broadcast (docs/
PROTOCOL.md §7.29's customization work) -- it isn't wired into
StreetPassResponder's outbound traffic yet (this project has never sent
its own non-empty Message/TMP Box list; 
honest-empty-list default). Nothing here has been live-tested as an
*outbound* payload a real console accepts -- only the read side (parsing
what a real console sends) is confirmed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import smdh

ENTRY_HEADER_SIZE = 8
ENTRY_HEADER = bytes(ENTRY_HEADER_SIZE)

DEFAULT_ENV_VAR = "STREETPASS_RECENTLY_PLAYED_FILE"


class RecentlyPlayedFileNotFound(FileNotFoundError):
    """No recently-played config file was found (see this module's docstring)."""


@dataclass(frozen=True)
class RecentlyPlayedTitle:
    """One "recently played" list entry: a title's SMDH banner text plus
    whatever icon bytes go with it (opaque, project findings -- pass
    b"" if you don't have real icon bytes for it; unconfirmed whether real
    hardware accepts that)."""

    title: smdh.Title
    icon: bytes = b""


def build_entry(entry: RecentlyPlayedTitle) -> bytes:
    return ENTRY_HEADER + smdh.build_title_table([entry.title]) + entry.icon


def build_recently_played_list(entries: List[RecentlyPlayedTitle]) -> bytes:
    return b"".join(build_entry(e) for e in entries)


def load_recently_played(path: Optional[str] = None) -> List[RecentlyPlayedTitle]:
    """Read a local JSON file listing "recently played" entries to
    broadcast. Expected shape:

        {"entries": [
            {"short_title": "...", "long_title": "...", "publisher": "...",
             "icon_file": "/optional/path/to/raw/icon/bytes"}
        ]}

    icon_file is optional; a real title's icon bytes extracted from a
    device dump can be pointed at here, but this project hasn't confirmed
    what a valid one looks like -- omit it to send
    no icon data at all.

    Args:
        path: explicit file path. If omitted, reads the
            STREETPASS_RECENTLY_PLAYED_FILE environment variable instead.
    """
    resolved = path or os.environ.get(DEFAULT_ENV_VAR)
    if not resolved:
        raise RecentlyPlayedFileNotFound(
            f"no recently-played config file given and {DEFAULT_ENV_VAR} is not set "
            " -- pass path= explicitly or set the env var"
        )
    with open(resolved) as f:
        data = json.load(f)
    entries = []
    for item in data["entries"]:
        icon = b""
        if item.get("icon_file"):
            icon = Path(item["icon_file"]).read_bytes()
        entries.append(RecentlyPlayedTitle(
            title=smdh.Title(
                short_description=item["short_title"],
                long_description=item["long_title"],
                publisher=item["publisher"],
            ),
            icon=icon,
        ))
    return entries
