"""Per-game StreetPass TMP Box data, kept separate from the box-editing
logic in mii_plaza_editor.py (2026-09-16, user request: 今後、ゲームごとに
自由にデータを書き換えられるようにしたいから、データだけ別枠に切り出す).

So far this project has only reverse-engineered Mii Plaza's own body
layout (docs/PROTOCOL_REFERENCE.md). The outer CecMessageHeader
(message_id, sender_id, batch_id, etc.) is a fixed, shared format used by
every StreetPass-enabled title (confirmed independently by the community
project NetPass) and stays defined once in
mii_plaza_editor.py -- only the game-specific pieces (the per-title HMAC
key stored in CecMBoxInfoHeader, and where inside the body a greeting
comment / Mii blob live, which necessarily differ per game's own body
format) belong here. Adding support for another StreetPass game later
should mean adding one more GameProfile entry, not touching TmpBox itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GameProfile:
    name: str
    title_id: int  # e.g. 0x00020800 for Mii Plaza
    hmac_key: bytes  # from that title's own CecMBoxInfoHeader.hmac_key

    # Body-relative offsets (from the start of the 0x6060 body, i.e.
    # total_header_size in TmpBox). None where this project hasn't mapped
    # that field for this game yet, or the game doesn't have it at all.
    comment_body_offset: Optional[int] = None
    comment_header_len: int = 16
    mii_blob_body_offset: Optional[int] = None


# docs/PROTOCOL_REFERENCE.md §7 -- the only game this project has actually
# mapped out. All offsets are body-relative (add total_header_size).
MII_PLAZA = GameProfile(
    name="Mii Plaza",
    title_id=0x00020800,
    hmac_key=b"15cqj40dsrtde8m0fs0cr0x2hzafbfkl",
    comment_body_offset=16224,
    comment_header_len=16,
    mii_blob_body_offset=14036,
)

GAME_PROFILES: dict[str, GameProfile] = {
    "miiplaza": MII_PLAZA,
}

DEFAULT_PROFILE = MII_PLAZA


def get_profile(name: str) -> GameProfile:
    try:
        return GAME_PROFILES[name.lower()]
    except KeyError:
        raise ValueError(
            f"unknown game profile {name!r}, known profiles: {sorted(GAME_PROFILES)}"
        ) from None
