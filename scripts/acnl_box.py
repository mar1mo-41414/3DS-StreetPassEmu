#!/usr/bin/env python3
"""Animal Crossing: New Leaf house messages (StreetPass kind 1): inspect one, or build one from a save file.

    python scripts/acnl_box.py show MESSAGE.bin
    python scripts/acnl_box.py from-save garden_plus.dat --id64 0011223344556677 -o msg.bin [--player 0] [--notice TEXT]
    python scripts/acnl_box.py from-save garden_plus.dat --other-town --player-name NAME --town-name TOWN \\
        [--town-id 0x1234] [--player-id 0x5678] [--id64 HEX] [--icon-from MESSAGE] --tmp-box -o box.bin

``show`` accepts a message from a CEC outbox/inbox or a received TMP Box (with its 0x14-byte header) and checks the magic,
the CRC-32C and the HMAC. A message built with ``from-save`` is from the *same* town as the save, and a game ignores
messages from its own town; ``--other-town`` rewrites the player id / name / town id / town name (random ids unless
given) so the receiving console takes it for a visitor. ``--tmp-box`` adds the TmpBoxHeader, giving the file that
``streetpass_loop.py --outbound-raw-tmp-box`` sends. Back up the receiving save first (JKSV).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from streetpass_emu import acnl  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sh = sub.add_parser("show")
    sh.add_argument("file", type=Path)
    fs = sub.add_parser("from-save")
    fs.add_argument("save", type=Path)
    fs.add_argument("--id64", default=None, help="16 hex digits (the sending console's id; random if omitted)")
    fs.add_argument("--other-town", action="store_true", help="pretend to come from another town")
    fs.add_argument("--player-name", default="")
    fs.add_argument("--town-name", default="")
    fs.add_argument("--player-id", type=lambda x: int(x, 0), default=None)
    fs.add_argument("--town-id", type=lambda x: int(x, 0), default=None)
    fs.add_argument("--icon-from", type=Path, default=None, help="take the 3200-byte icon from this message")
    fs.add_argument("--tmp-box", action="store_true", help="prepend the TmpBoxHeader")
    fs.add_argument("--player", type=int, default=0)
    fs.add_argument("--notice", default="")
    fs.add_argument("-o", "--output", required=True, type=Path)
    a = ap.parse_args()
    if a.cmd == "show":
        r = acnl.parse_message(a.file.read_bytes())
        m = r.message
        print(f"userData {r.user_data}  magic {'OK' if r.magic_ok else 'NG'}  CRC-32C {'OK' if r.crc_ok else 'NG'}  "
              f"HMAC {'OK' if r.hmac_ok else 'NG'}")
        print(f"notice   : {m.notice!r}")
        print(f"player   : {m.player_name!r} (id {m.player_id:#06x})   town: {m.town_name!r} (id {m.town_id:#06x})")
        print(f"sender id: {m.id64.hex()}   message id: {m.message_id.hex() if m.message_id else '-'}   created: {m.created}")
        return 0 if (r.magic_ok and r.crc_ok and r.hmac_ok) else 1
    id64 = bytes.fromhex(a.id64) if a.id64 else os.urandom(8)
    msg = acnl.from_save(a.save.read_bytes(), id64, a.player, a.notice)
    if a.icon_from:
        msg.icon = acnl.parse_message(a.icon_from.read_bytes()).message.icon
    if a.other_town:
        if not (a.player_name and a.town_name):
            ap.error("--other-town needs --player-name and --town-name")
        town_id = a.town_id if a.town_id is not None else int.from_bytes(os.urandom(2), "little")
        player_id = a.player_id if a.player_id is not None else int.from_bytes(os.urandom(2), "little")
        if town_id == msg.town_id:
            ap.error("the town id must differ from the save's own")
        msg.player = acnl.retarget_identity(msg.player, player_id=player_id, player_name=a.player_name,
                                            town_id=town_id, town_name=a.town_name)
        if not a.notice:
            msg.notice = f"{a.town_name}\n{a.player_name}"
    data = msg.build()
    if a.tmp_box:
        data = acnl.wrap_tmp_box(data)
    a.output.write_bytes(data)
    print(f"wrote {a.output} ({len(data)} bytes): {msg.notice!r}  player {msg.player_name!r} {msg.player_id:#06x}  "
          f"town {msg.town_name!r} {msg.town_id:#06x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
