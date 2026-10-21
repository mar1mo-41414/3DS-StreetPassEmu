#!/usr/bin/env python3
"""Animal Crossing: New Leaf house messages (StreetPass kind 1): inspect one, or build one from a save file.

    python scripts/acnl_box.py show MESSAGE.bin
    python scripts/acnl_box.py from-save garden_plus.dat --id64 0011223344556677 -o msg.bin [--player 0] [--notice TEXT]

``show`` accepts a message from a CEC outbox/inbox or a received TMP Box (with its 0x14-byte header) and checks the magic,
the CRC-32C and the HMAC. A message built with ``from-save`` is from the *same* town as the save: a game ignores
messages from its own town, so to try one on a real console its town must differ (not implemented yet).
"""
from __future__ import annotations

import argparse
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
    fs.add_argument("--id64", required=True, help="16 hex digits (the sending console's id)")
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
    msg = acnl.from_save(a.save.read_bytes(), bytes.fromhex(a.id64), a.player, a.notice)
    a.output.write_bytes(msg.build())
    print(f"wrote {a.output} ({len(msg.build())} bytes): {msg.notice!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
